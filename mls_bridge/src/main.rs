//! Bridge OpenMLS cho SecChat — chạy MLS (RFC 9420) thật bằng Rust.
//!
//! Tiến trình này là "động cơ" của group E2EE: client Python gửi command JSON
//! qua stdin (chế độ `serve`), bridge thực thi bằng thư viện OpenMLS rồi trả kết
//! quả JSON qua stdout. Toàn bộ logic nhạy cảm (TreeKEM, Welcome, Commit, key
//! schedule, mã hóa application) nằm ở đây — Python chỉ điều phối I/O.
//!
//! Ciphersuite mặc định là **X-Wing**
//! (`MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519`): KEM lai ML-KEM-768 +
//! X25519 cho confidentiality hậu lượng tử, chữ ký Ed25519 cổ điển cho
//! authentication (vì vậy `PQ_AUTHENTICATION = false`).
//!
//! Vai trò "validator": server gọi các lệnh validate trên **public group state**
//! để từ chối KeyPackage sai ciphersuite / commit giả mạo / nằm ngoài policy mà
//! KHÔNG cần biết group secret — đó là lý do nhiều hàm thao tác trên `PublicGroup`
//! thay vì `MlsGroup` đầy đủ.

use std::collections::HashMap;
use std::io::{self, BufRead, Write};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openmls::prelude::group_info::{GroupInfo, VerifiableGroupInfo};
use openmls::prelude::{tls_codec::*, *};
use openmls_basic_credential::SignatureKeyPair;
use openmls_libcrux_crypto::CryptoProvider as LibcruxCryptoProvider;
use openmls_memory_storage::{MemoryStorage, MemoryStorageError};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

const OPENMLS_VERSION: &str = "0.8.1";
const PQ_HYBRID: bool = true; // confidentiality hậu lượng tử (X-Wing)
const PQ_AUTHENTICATION: bool = false; // chữ ký vẫn là Ed25519 cổ điển
const DEFAULT_CIPHERSUITE: Ciphersuite =
    Ciphersuite::MLS_256_XWING_CHACHA20POLY1305_SHA256_Ed25519;

/// Provider OpenMLS cho SecChat: gộp nhà cung cấp crypto (libcrux, có X-Wing) và
/// kho lưu trạng thái trong RAM. Một provider tương ứng một phiên người dùng.
struct BridgeProvider {
    crypto: LibcruxCryptoProvider,
    storage: MemoryStorage,
}

impl BridgeProvider {
    fn from_storage(storage: MemoryStorage) -> Self {
        Self {
            crypto: LibcruxCryptoProvider::new()
                .expect("libcrux crypto provider initialization failed"),
            storage,
        }
    }
}

impl Default for BridgeProvider {
    fn default() -> Self {
        Self {
            crypto: LibcruxCryptoProvider::new()
                .expect("libcrux crypto provider initialization failed"),
            storage: MemoryStorage::default(),
        }
    }
}

impl openmls_traits::OpenMlsProvider for BridgeProvider {
    type CryptoProvider = LibcruxCryptoProvider;
    type RandProvider = LibcruxCryptoProvider;
    type StorageProvider = MemoryStorage;

    fn storage(&self) -> &Self::StorageProvider {
        &self.storage
    }

    fn crypto(&self) -> &Self::CryptoProvider {
        &self.crypto
    }

    fn rand(&self) -> &Self::RandProvider {
        &self.crypto
    }
}

fn ciphersuite_name() -> String {
    format!("{DEFAULT_CIPHERSUITE:?}")
}

fn ciphersuite_metadata() -> Value {
    json!({
        "backend": "openmls",
        "openmls": OPENMLS_VERSION,
        "ciphersuite": ciphersuite_name(),
        "pq_hybrid": PQ_HYBRID,
        "pq_authentication": PQ_AUTHENTICATION,
        "pq_kem": "X-Wing draft hybrid KEM (ML-KEM-768 + X25519)",
        "pq_authentication_note": "MLS signatures remain Ed25519 classical authentication",
    })
}

fn with_ciphersuite_metadata(mut value: Value) -> Value {
    if let Value::Object(ref mut obj) = value {
        if let Value::Object(meta) = ciphersuite_metadata() {
            for (key, val) in meta {
                obj.entry(key).or_insert(val);
            }
        }
    }
    value
}

/// Chỉ chấp nhận đúng ciphersuite X-Wing mặc định; từ chối mọi ciphersuite khác
/// (chống hạ cấp xuống suite yếu/không hậu lượng tử).
fn ensure_default_ciphersuite_name(name: &str) -> Result<Ciphersuite, String> {
    let expected = ciphersuite_name();
    if name == expected {
        Ok(DEFAULT_CIPHERSUITE)
    } else {
        Err(format!(
            "unsupported MLS ciphersuite {name}; expected {expected}"
        ))
    }
}

fn b64e(raw: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(raw)
}

fn b64d(text: &str) -> Result<Vec<u8>, String> {
    URL_SAFE_NO_PAD
        .decode(text.as_bytes())
        .map_err(|err| format!("base64 decode failed: {err}"))
}

fn credential_with_key(
    identity: &[u8],
    signature_algorithm: SignatureScheme,
    provider: &impl OpenMlsProvider,
) -> Result<(CredentialWithKey, SignatureKeyPair), String> {
    let credential = BasicCredential::new(identity.to_vec());
    let signer = SignatureKeyPair::new(signature_algorithm)
        .map_err(|err| format!("signature key generation failed: {err:?}"))?;
    signer
        .store(provider.storage())
        .map_err(|err| format!("signature key store failed: {err:?}"))?;
    Ok((
        CredentialWithKey {
            credential: credential.into(),
            signature_key: signer.public().into(),
        },
        signer,
    ))
}

fn key_package(
    ciphersuite: Ciphersuite,
    provider: &impl OpenMlsProvider,
    signer: &SignatureKeyPair,
    credential: CredentialWithKey,
) -> Result<KeyPackageBundle, String> {
    KeyPackage::builder()
        .build(ciphersuite, provider, signer, credential)
        .map_err(|err| format!("key package build failed: {err:?}"))
}

fn protocol_message(bytes: &[u8]) -> Result<ProtocolMessage, String> {
    let message = MlsMessageIn::tls_deserialize(&mut bytes.as_ref())
        .map_err(|err| format!("MLS message deserialize failed: {err:?}"))?;
    message
        .try_into_protocol_message()
        .map_err(|err| format!("not a protocol message: {err:?}"))
}

/// Giải mã rồi VALIDATE một KeyPackage nhận từ ngoài (kiểm chữ ký + protocol
/// version). Validate trước khi dùng để tránh kết nạp KeyPackage giả mạo.
fn parse_key_package(provider: &impl OpenMlsProvider, b64: &str) -> Result<KeyPackage, String> {
    let bytes = b64d(b64)?;
    let key_package_in = KeyPackageIn::tls_deserialize(&mut bytes.as_slice())
        .map_err(|err| format!("KeyPackage deserialize failed: {err:?}"))?;
    key_package_in
        .validate(provider.crypto(), ProtocolVersion::Mls10)
        .map_err(|err| format!("KeyPackage validate failed: {err:?}"))
}

fn mls_message_bytes(out: MlsMessageOut) -> Result<String, String> {
    out.tls_serialize_detached()
        .map(|bytes| b64e(&bytes))
        .map_err(|err| format!("MLS message serialize failed: {err:?}"))
}

fn group_info_b64(group_info: Option<GroupInfo>) -> Result<Value, String> {
    match group_info {
        Some(info) => Ok(Value::String(b64e(
            &info
                .tls_serialize_detached()
                .map_err(|err| format!("GroupInfo serialize failed: {err:?}"))?,
        ))),
        None => Ok(Value::Null),
    }
}

fn ratchet_tree_b64(group: &MlsGroup) -> Result<String, String> {
    group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map(|bytes| b64e(&bytes))
        .map_err(|err| format!("RatchetTree serialize failed: {err:?}"))
}

fn public_ratchet_tree_b64(group: &PublicGroup) -> Result<String, String> {
    group
        .export_ratchet_tree()
        .tls_serialize_detached()
        .map(|bytes| b64e(&bytes))
        .map_err(|err| format!("public RatchetTree serialize failed: {err:?}"))
}

fn parse_ratchet_tree(b64: &str) -> Result<RatchetTreeIn, String> {
    let bytes = b64d(b64)?;
    RatchetTreeIn::tls_deserialize(&mut bytes.as_slice())
        .map_err(|err| format!("RatchetTree deserialize failed: {err:?}"))
}

fn parse_group_info(b64: &str) -> Result<VerifiableGroupInfo, String> {
    let bytes = b64d(b64)?;
    VerifiableGroupInfo::tls_deserialize(&mut bytes.as_slice())
        .map_err(|err| format!("GroupInfo deserialize failed: {err:?}"))
}

fn export_public_state(provider: &BridgeProvider) -> Result<String, String> {
    let mut storage_bytes = Vec::new();
    provider
        .storage()
        .serialize(&mut storage_bytes)
        .map_err(|err| format!("public MLS storage export failed: {err}"))?;
    Ok(b64e(&storage_bytes))
}

fn provider_from_public_state(state_b64: Option<&str>) -> Result<BridgeProvider, String> {
    match state_b64 {
        Some(text) if !text.is_empty() => {
            let storage_bytes = b64d(text)?;
            let storage = MemoryStorage::deserialize(&mut storage_bytes.as_slice())
                .map_err(|err| format!("public MLS storage import failed: {err}"))?;
            Ok(BridgeProvider::from_storage(storage))
        }
        _ => Ok(BridgeProvider::default()),
    }
}

/// Nạp PublicGroup (view công khai, không có secret) của một hội thoại từ storage.
fn public_group_for(provider: &BridgeProvider, conversation_id: i64) -> Result<PublicGroup, String> {
    PublicGroup::load(provider.storage(), &group_id_for(conversation_id))
        .map_err(|err| format!("public group load failed: {err:?}"))?
        .ok_or_else(|| format!("public MLS group state missing for conversation {conversation_id}"))
}

/// Rút danh sách user_id thành viên (đã sort + khử trùng) từ public group.
fn sorted_member_ids(group: &PublicGroup) -> Vec<i64> {
    let mut ids: Vec<i64> = group
        .members()
        .filter_map(|member| credential_user_id(member.credential.serialized_content()))
        .collect();
    ids.sort_unstable();
    ids.dedup();
    ids
}

fn expected_member_ids(req: &Command) -> Vec<i64> {
    let mut ids = req.expected_member_ids.clone().unwrap_or_default();
    ids.retain(|uid| *uid > 0);
    ids.sort_unstable();
    ids.dedup();
    ids
}

/// Kiểm tra một public group hợp lệ: đúng ciphersuite X-Wing, đúng group id của
/// hội thoại, và tập thành viên thực tế KHỚP với tập kỳ vọng. Đây là lõi của
/// "MLS validator" mà server dựa vào để chấp nhận/từ chối thay đổi membership.
fn validate_public_group_common(
    group: &PublicGroup,
    conversation_id: i64,
    expected_members: &[i64],
) -> Result<(), String> {
    if group.ciphersuite() != DEFAULT_CIPHERSUITE {
        return Err(format!(
            "MLS validation failed: unsupported ciphersuite {:?}",
            group.ciphersuite()
        ));
    }
    if group.group_id() != &group_id_for(conversation_id) {
        return Err("MLS validation failed: group id mismatch".into());
    }
    let actual = sorted_member_ids(group);
    if !expected_members.is_empty() && actual != expected_members {
        return Err(format!(
            "MLS validation failed: member set mismatch actual={actual:?} expected={expected_members:?}"
        ));
    }
    Ok(())
}

fn public_group_response(
    provider: &BridgeProvider,
    group: &PublicGroup,
    conversation_id: i64,
) -> Result<Value, String> {
    Ok(with_ciphersuite_metadata(json!({
        "ok": true,
        "conversation_id": conversation_id,
        "epoch": group.group_context().epoch().as_u64(),
        "member_ids": sorted_member_ids(group),
        "public_state_b64": export_public_state(provider)?,
        "public_state_hash": b64e(&Sha256::digest(export_public_state(provider)?.as_bytes())),
        "ratchet_tree_b64": public_ratchet_tree_b64(group)?,
        "validation_backend": "openmls_public_group",
    })))
}

/// Dựng PublicGroup từ GroupInfo + RatchetTree do client gửi (xác minh chữ ký
/// nội tại) rồi chạy [`validate_public_group_common`]. Cho phép server kiểm một
/// group state "từ ngoài" mà KHÔNG cần group secret.
fn validate_external_group_info(
    provider: &BridgeProvider,
    conversation_id: i64,
    group_info_b64: &str,
    ratchet_tree_b64_text: &str,
    expected_members: &[i64],
) -> Result<PublicGroup, String> {
    let (group, _) = PublicGroup::from_external(
        provider.crypto(),
        provider.storage(),
        parse_ratchet_tree(ratchet_tree_b64_text)?,
        parse_group_info(group_info_b64)?,
        ProposalStore::new(),
    )
    .map_err(|err| format!("MLS validation failed: GroupInfo/RatchetTree invalid: {err:?}"))?;
    validate_public_group_common(&group, conversation_id, expected_members)?;
    Ok(group)
}

fn bridge_group_key(conversation_id: i64) -> String {
    conversation_id.to_string()
}

/// Sinh GroupId MLS tất định từ conversation_id (cùng conv → cùng group id).
fn group_id_for(conversation_id: i64) -> GroupId {
    GroupId::from_slice(format!("secchat-group:{conversation_id}").as_bytes())
}

/// Rút user_id SecChat từ nội dung credential JSON của một thành viên (None nếu hỏng).
fn credential_user_id(bytes: &[u8]) -> Option<i64> {
    serde_json::from_slice::<Value>(bytes)
        .ok()
        .and_then(|v| v.get("user_id").and_then(Value::as_i64))
}

/// Trạng thái MLS sống của MỘT phiên người dùng: provider (crypto + storage),
/// credential/signer của chính mình, và bản đồ các group đang tham gia.
#[derive(Default)]
struct BridgeState {
    provider: BridgeProvider,
    ciphersuite: Option<Ciphersuite>,
    credential_identity: Option<Vec<u8>>,
    credential: Option<CredentialWithKey>,
    signer: Option<SignatureKeyPair>,
    groups: HashMap<String, MlsGroup>,
}

/// Ảnh chụp tuần tự hóa của BridgeState để client lưu mã hóa cục bộ và khôi phục
/// sau relogin (gồm storage, signer, credential và danh sách conversation group).
#[derive(serde::Serialize, serde::Deserialize)]
struct BridgeSnapshot {
    schema_version: u32,
    ciphersuite: String,
    credential_identity_b64: String,
    signer_b64: String,
    storage_b64: String,
    groups: Vec<i64>,
}

impl BridgeState {
    /// Ciphersuite đang dùng (mặc định X-Wing nếu chưa init identity).
    fn ciphersuite(&self) -> Ciphersuite {
        self.ciphersuite.unwrap_or(DEFAULT_CIPHERSUITE)
    }

    /// Lấy signing key MLS; lỗi nếu identity chưa được khởi tạo.
    fn signer(&self) -> Result<&SignatureKeyPair, String> {
        self.signer
            .as_ref()
            .ok_or_else(|| "MLS identity is not initialized".to_string())
    }

    /// Lấy credential MLS (clone); lỗi nếu identity chưa được khởi tạo.
    fn credential(&self) -> Result<CredentialWithKey, String> {
        self.credential
            .clone()
            .ok_or_else(|| "MLS identity is not initialized".to_string())
    }

    /// Đóng gói toàn bộ state (storage + signer + credential + groups) thành một
    /// snapshot base64 để Python lưu mã hóa bằng master key.
    fn export_state(&self) -> Result<Value, String> {
        let signer = self.signer()?;
        let identity = self
            .credential_identity
            .as_ref()
            .ok_or_else(|| "MLS credential identity is not initialized".to_string())?;
        let mut storage_bytes = Vec::new();
        self.provider
            .storage()
            .serialize(&mut storage_bytes)
            .map_err(|err| format!("MLS storage export failed: {err}"))?;
        let signer_bytes = serde_json::to_vec(signer)
            .map_err(|err| format!("MLS signer export failed: {err}"))?;
        let mut groups: Vec<i64> = self
            .groups
            .keys()
            .filter_map(|key| key.parse::<i64>().ok())
            .collect();
        groups.sort_unstable();
        groups.dedup();
        let snapshot = BridgeSnapshot {
            schema_version: 1,
            ciphersuite: format!("{:?}", self.ciphersuite()),
            credential_identity_b64: b64e(identity),
            signer_b64: b64e(&signer_bytes),
            storage_b64: b64e(&storage_bytes),
            groups,
        };
        let snapshot_bytes = serde_json::to_vec(&snapshot)
            .map_err(|err| format!("MLS state encode failed: {err}"))?;
        Ok(json!({
            "ok": true,
            "schema_version": snapshot.schema_version,
            "state_b64": b64e(&snapshot_bytes),
            "groups": snapshot.groups,
            "credential_identity_b64": snapshot.credential_identity_b64,
        }))
    }

    /// Khôi phục state từ snapshot đã lưu; kiểm schema + ciphersuite, nạp lại
    /// storage/signer/credential và load lại từng MlsGroup.
    fn import_state(&mut self, state_b64: &str) -> Result<Value, String> {
        let snapshot_bytes = b64d(state_b64)?;
        let snapshot: BridgeSnapshot = serde_json::from_slice(&snapshot_bytes)
            .map_err(|err| format!("MLS state decode failed: {err}"))?;
        if snapshot.schema_version != 1 {
            return Err(format!(
                "unsupported MLS state schema {}",
                snapshot.schema_version
            ));
        }
        let storage_bytes = b64d(&snapshot.storage_b64)?;
        let storage = MemoryStorage::deserialize(&mut storage_bytes.as_slice())
            .map_err(|err| format!("MLS storage import failed: {err}"))?;
        let provider = BridgeProvider::from_storage(storage);
        let signer_bytes = b64d(&snapshot.signer_b64)?;
        let signer: SignatureKeyPair = serde_json::from_slice(&signer_bytes)
            .map_err(|err| format!("MLS signer import failed: {err}"))?;
        signer
            .store(provider.storage())
            .map_err(|err: MemoryStorageError| format!("MLS signer store failed: {err:?}"))?;
        let identity_bytes = b64d(&snapshot.credential_identity_b64)?;
        let ciphersuite = ensure_default_ciphersuite_name(&snapshot.ciphersuite)?;
        let credential = CredentialWithKey {
            credential: BasicCredential::new(identity_bytes.clone()).into(),
            signature_key: signer.public().into(),
        };
        let mut groups = HashMap::new();
        for conversation_id in snapshot.groups.iter().copied() {
            let group_id = group_id_for(conversation_id);
            match MlsGroup::load(provider.storage(), &group_id)
                .map_err(|err| format!("MLS group load failed: {err:?}"))?
            {
                Some(group) => {
                    groups.insert(bridge_group_key(conversation_id), group);
                }
                None => {
                    return Err(format!(
                        "MLS group state missing for conversation {conversation_id}"
                    ));
                }
            }
        }
        self.provider = provider;
        self.ciphersuite = Some(ciphersuite);
        self.credential_identity = Some(identity_bytes);
        self.credential = Some(credential);
        self.signer = Some(signer);
        self.groups = groups;
        Ok(with_ciphersuite_metadata(json!({
            "ok": true,
            "schema_version": snapshot.schema_version,
            "groups": snapshot.groups,
            "credential_identity_b64": snapshot.credential_identity_b64,
        })))
    }

    /// Bộ điều phối lệnh: nhận một Command đã parse rồi gọi đúng thao tác MLS,
    /// trả về JSON kết quả (kèm metadata ciphersuite). Mọi lỗi trả dạng Err(String).
    fn handle(&mut self, req: Command) -> Result<Value, String> {
        match req.cmd.as_str() {
            "version" | "status" => Ok(with_ciphersuite_metadata(json!({
                "ok": true
            }))),
            "init_identity" => {
                let identity = json!({
                    "user_id": req.user_id.unwrap_or(0),
                    "email": req.email.unwrap_or_default(),
                    "secchat_identity_pk": req.secchat_identity_pk.unwrap_or_default(),
                    "secchat_identity_version": req.secchat_identity_version.unwrap_or(0),
                });
                let ciphersuite = DEFAULT_CIPHERSUITE;
                let identity_bytes = serde_json::to_vec(&identity)
                    .map_err(|err| format!("identity encode failed: {err}"))?;
                let (credential, signer) = credential_with_key(
                    &identity_bytes,
                    ciphersuite.signature_algorithm(),
                    &self.provider,
                )?;
                self.ciphersuite = Some(ciphersuite);
                self.credential_identity = Some(identity_bytes.clone());
                self.credential = Some(credential);
                self.signer = Some(signer);
                Ok(with_ciphersuite_metadata(json!({
                    "ok": true,
                    "credential_identity_b64": b64e(&identity_bytes)
                })))
            }
            "export_state" => self.export_state(),
            "import_state" => {
                let state_b64 = req.state_b64.ok_or("state_b64 missing")?;
                self.import_state(&state_b64)
            }
            "top_up_key_packages" => {
                let count = req.count.unwrap_or(8).clamp(1, 64);
                let signer = self.signer()?;
                let credential = self.credential()?;
                let ciphersuite = self.ciphersuite();
                let mut out = Vec::new();
                for _ in 0..count {
                    let bundle = key_package(
                        ciphersuite,
                        &self.provider,
                        signer,
                        credential.clone(),
                    )?;
                    let bytes = bundle
                        .key_package()
                        .tls_serialize_detached()
                        .map_err(|err| format!("KeyPackage serialize failed: {err:?}"))?;
                    let hash = Sha256::digest(&bytes);
                    out.push(json!({
                        "key_package_ref": b64e(&hash),
                        "key_package_b64": b64e(&bytes),
                        "ciphersuite": format!("{ciphersuite:?}")
                    }));
                }
                Ok(with_ciphersuite_metadata(json!({"ok": true, "key_packages": out})))
            }
            "create_group" => {
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let config = MlsGroupCreateConfig::builder()
                    .ciphersuite(self.ciphersuite())
                    .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .use_ratchet_tree_extension(true)
                    .build();
                let group = MlsGroup::new_with_group_id(
                    &self.provider,
                    self.signer()?,
                    &config,
                    group_id_for(conversation_id),
                    self.credential()?,
                )
                .map_err(|err| format!("group create failed: {err:?}"))?;
                let epoch = group.epoch().as_u64();
                self.groups
                    .insert(bridge_group_key(conversation_id), group);
                Ok(with_ciphersuite_metadata(json!({
                    "ok": true,
                    "conversation_id": conversation_id,
                    "epoch": epoch,
                    "group_id_b64": b64e(format!("secchat-group:{conversation_id}").as_bytes()),
                    "ratchet_tree_b64": ratchet_tree_b64(self.groups
                        .get(&bridge_group_key(conversation_id))
                        .ok_or("created MLS group state missing")?)?
                })))
            }
            "add_members" => {
                // Thêm member: parse+validate KeyPackage, tạo Commit+Welcome, merge → epoch mới.
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let packages: Vec<KeyPackage> = req
                    .key_packages
                    .unwrap_or_default()
                    .iter()
                    .map(|kp| parse_key_package(&self.provider, kp))
                    .collect::<Result<Vec<_>, _>>()?;
                if packages.is_empty() {
                    return Err("no KeyPackage provided".into());
                }
                let signer = self.signer()?.clone();
                let key = bridge_group_key(conversation_id);
                let mut group = self.groups.remove(&key)
                    .ok_or_else(|| format!("MLS group state missing for conversation {conversation_id}"))?;
                let result = (|| {
                    let (commit, welcome, group_info) = group
                        .add_members(&self.provider, &signer, &packages)
                        .map_err(|err| format!("add members failed: {err:?}"))?;
                    group
                        .merge_pending_commit(&self.provider)
                        .map_err(|err| format!("merge add commit failed: {err:?}"))?;
                    Ok(with_ciphersuite_metadata(json!({
                        "ok": true,
                        "conversation_id": conversation_id,
                        "epoch": group.epoch().as_u64(),
                        "commit_b64": mls_message_bytes(commit)?,
                        "welcome_b64": mls_message_bytes(welcome)?,
                        "group_info_b64": group_info_b64(group_info)?,
                        "ratchet_tree_b64": ratchet_tree_b64(&group)?
                    })))
                })();
                self.groups.insert(key, group);
                result
            }
            "remove_members" => {
                // Loại member: tìm leaf theo user_id, tạo Commit, merge → epoch mới (PCS).
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let remove_user_ids = req.user_ids.unwrap_or_default();
                if remove_user_ids.is_empty() {
                    return Err("user_ids missing".into());
                }
                let signer = self.signer()?.clone();
                let key = bridge_group_key(conversation_id);
                let mut group = self.groups.remove(&key)
                    .ok_or_else(|| format!("MLS group state missing for conversation {conversation_id}"))?;
                let result = (|| {
                    let mut leaf_indices = Vec::new();
                    for member in group.members() {
                        let uid = credential_user_id(member.credential.serialized_content());
                        if uid.map(|u| remove_user_ids.contains(&u)).unwrap_or(false) {
                            leaf_indices.push(member.index);
                        }
                    }
                    if leaf_indices.is_empty() {
                        return Err("no matching MLS members to remove".into());
                    }
                    let (commit, welcome, group_info) = group
                        .remove_members(&self.provider, &signer, &leaf_indices)
                        .map_err(|err| format!("remove members failed: {err:?}"))?;
                    group
                        .merge_pending_commit(&self.provider)
                        .map_err(|err| format!("merge remove commit failed: {err:?}"))?;
                    Ok(with_ciphersuite_metadata(json!({
                        "ok": true,
                        "conversation_id": conversation_id,
                        "epoch": group.epoch().as_u64(),
                        "commit_b64": mls_message_bytes(commit)?,
                        "welcome_b64": match welcome {
                            Some(w) => Value::String(mls_message_bytes(w)?),
                            None => Value::Null,
                        },
                        "group_info_b64": group_info_b64(group_info)?,
                        "ratchet_tree_b64": ratchet_tree_b64(&group)?
                    })))
                })();
                self.groups.insert(key, group);
                result
            }
            "join_from_welcome" => {
                // Thành viên mới: parse Welcome → dựng MlsGroup ở epoch hiện hành.
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let welcome_b64 = req.welcome_b64.ok_or("welcome_b64 missing")?;
                let welcome_bytes = b64d(&welcome_b64)?;
                let welcome_in = MlsMessageIn::tls_deserialize(&mut welcome_bytes.as_slice())
                    .map_err(|err| format!("welcome deserialize failed: {err:?}"))?;
                let welcome = match welcome_in.extract() {
                    MlsMessageBodyIn::Welcome(welcome) => welcome,
                    _ => return Err("expected Welcome message".into()),
                };
                let join_config = MlsGroupJoinConfig::builder()
                    .wire_format_policy(MIXED_PLAINTEXT_WIRE_FORMAT_POLICY)
                    .use_ratchet_tree_extension(true)
                    .build();
                let staged = StagedWelcome::new_from_welcome(
                    &self.provider,
                    &join_config,
                    welcome,
                    None,
                )
                .map_err(|err| format!("staged welcome failed: {err:?}"))?;
                let group = staged
                    .into_group(&self.provider)
                    .map_err(|err| format!("welcome join failed: {err:?}"))?;
                let epoch = group.epoch().as_u64();
                self.groups
                    .insert(bridge_group_key(conversation_id), group);
                Ok(with_ciphersuite_metadata(json!({
                    "ok": true,
                    "conversation_id": conversation_id,
                    "epoch": epoch
                })))
            }
            "process_commit" => {
                // Áp Commit nhận được: process + merge staged commit → epoch mới.
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let commit_b64 = req.commit_b64.ok_or("commit_b64 missing")?;
                let commit_bytes = b64d(&commit_b64)?;
                let key = bridge_group_key(conversation_id);
                let mut group = self.groups.remove(&key)
                    .ok_or_else(|| format!("MLS group state missing for conversation {conversation_id}"))?;
                let result = (|| {
                    let processed = group
                        .process_message(&self.provider, protocol_message(&commit_bytes)?)
                        .map_err(|err| format!("process commit failed: {err:?}"))?;
                    let content = processed.into_content();
                    match content {
                        ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                            group
                                .merge_staged_commit(&self.provider, *staged_commit)
                                .map_err(|err| format!("merge commit failed: {err:?}"))?;
                        }
                        other => return Err(format!("expected staged commit, got {other:?}")),
                    }
                    Ok(with_ciphersuite_metadata(json!({
                        "ok": true,
                        "conversation_id": conversation_id,
                        "epoch": group.epoch().as_u64(),
                        "active": group.is_active()
                    })))
                })();
                self.groups.insert(key, group);
                result
            }
            "encrypt_application" => {
                // Mã hóa một application message bằng khóa epoch hiện tại.
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let plaintext_b64 = req.plaintext_b64.ok_or("plaintext_b64 missing")?;
                let plaintext = b64d(&plaintext_b64)?;
                let signer = self.signer()?.clone();
                let key = bridge_group_key(conversation_id);
                let mut group = self.groups.remove(&key)
                    .ok_or_else(|| format!("MLS group state missing for conversation {conversation_id}"))?;
                let result = (|| {
                    let out = group
                        .create_message(&self.provider, &signer, &plaintext)
                        .map_err(|err| format!("create app message failed: {err:?}"))?;
                    Ok(with_ciphersuite_metadata(json!({
                        "ok": true,
                        "conversation_id": conversation_id,
                        "epoch": group.epoch().as_u64(),
                        "message_b64": mls_message_bytes(out)?
                    })))
                })();
                self.groups.insert(key, group);
                result
            }
            "decrypt_application" => {
                // Giải mã một application message; chỉ chấp nhận đúng loại ApplicationMessage.
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let message_b64 = req.message_b64.ok_or("message_b64 missing")?;
                let message_bytes = b64d(&message_b64)?;
                let key = bridge_group_key(conversation_id);
                let mut group = self.groups.remove(&key)
                    .ok_or_else(|| format!("MLS group state missing for conversation {conversation_id}"))?;
                let result = (|| {
                    let processed = group
                        .process_message(&self.provider, protocol_message(&message_bytes)?)
                        .map_err(|err| format!("process app message failed: {err:?}"))?;
                    let content = processed.into_content();
                    match content {
                        ProcessedMessageContent::ApplicationMessage(msg) => Ok(with_ciphersuite_metadata(json!({
                            "ok": true,
                            "conversation_id": conversation_id,
                            "epoch": group.epoch().as_u64(),
                            "plaintext_b64": b64e(&msg.into_bytes())
                        }))),
                        other => Err(format!("expected application message, got {other:?}")),
                    }
                })();
                self.groups.insert(key, group);
                result
            }
            "validate_group_create" => {
                // VALIDATE (server gọi): dựng public group từ GroupInfo+tree client gửi rồi kiểm hợp lệ.
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let group_info_b64 = req.group_info_b64.as_deref().ok_or("group_info_b64 missing")?;
                let ratchet_tree_b64_text = req
                    .ratchet_tree_b64
                    .as_deref()
                    .ok_or("ratchet_tree_b64 missing")?;
                let expected = expected_member_ids(&req);
                let provider = provider_from_public_state(None)?;
                let group = validate_external_group_info(
                    &provider,
                    conversation_id,
                    group_info_b64,
                    ratchet_tree_b64_text,
                    &expected,
                )?;
                public_group_response(&provider, &group, conversation_id)
            }
            "validate_group_commit" => {
                // VALIDATE (server gọi): áp thử Commit trên public state, kiểm actor + tập thành viên kỳ vọng.
                let conversation_id = req.conversation_id.ok_or("conversation_id missing")?;
                let public_state_b64 = req
                    .public_state_b64
                    .as_deref()
                    .ok_or("public_state_b64 missing")?;
                let commit_b64 = req.commit_b64.as_deref().ok_or("commit_b64 missing")?;
                let group_info_b64 = req.group_info_b64.as_deref().ok_or("group_info_b64 missing")?;
                let ratchet_tree_b64_text = req
                    .ratchet_tree_b64
                    .as_deref()
                    .ok_or("ratchet_tree_b64 missing")?;
                let expected = expected_member_ids(&req);
                let provider = provider_from_public_state(Some(public_state_b64))?;
                let mut group = public_group_for(&provider, conversation_id)?;
                validate_public_group_common(&group, conversation_id, &[])?;
                let commit_bytes = b64d(commit_b64)?;
                let processed = group
                    .process_message(provider.crypto(), protocol_message(&commit_bytes)?)
                    .map_err(|err| format!("MLS validation failed: commit invalid: {err:?}"))?;
                let actor_user_id =
                    credential_user_id(processed.credential().serialized_content()).unwrap_or(0);
                if let Some(expected_actor) = req.actor_user_id {
                    if expected_actor > 0 && actor_user_id != expected_actor {
                        return Err(format!(
                            "MLS validation failed: actor credential mismatch: expected {expected_actor}, got {actor_user_id}"
                        ));
                    }
                }
                match processed.into_content() {
                    ProcessedMessageContent::StagedCommitMessage(staged_commit) => {
                        group
                            .merge_commit(provider.storage(), *staged_commit)
                            .map_err(|err| format!("MLS validation failed: merge commit failed: {err:?}"))?;
                    }
                    other => {
                        return Err(format!(
                            "MLS validation failed: expected staged commit, got {other:?}"
                        ))
                    }
                }
                validate_public_group_common(&group, conversation_id, &expected)?;

                let check_provider = provider_from_public_state(None)?;
                let external_group = validate_external_group_info(
                    &check_provider,
                    conversation_id,
                    group_info_b64,
                    ratchet_tree_b64_text,
                    &expected,
                )?;
                if external_group.group_context().epoch() != group.group_context().epoch() {
                    return Err("MLS validation failed: GroupInfo epoch mismatch".into());
                }
                public_group_response(&provider, &group, conversation_id)
            }
            "selftest" => selftest(),
            other => Err(format!("unknown command: {other}")),
        }
    }
}

/// Một lệnh JSON nhận từ client: trường `cmd` chọn thao tác, các trường còn lại
/// là tham số tùy lệnh (đều Option để cùng một struct phục vụ mọi lệnh).
#[derive(Clone, Debug, Default, serde::Deserialize)]
struct Command {
    cmd: String,
    #[serde(default)]
    user_id: Option<i64>,
    #[serde(default)]
    email: Option<String>,
    #[serde(default)]
    secchat_identity_pk: Option<String>,
    #[serde(default)]
    secchat_identity_version: Option<i64>,
    #[serde(default)]
    count: Option<usize>,
    #[serde(default)]
    conversation_id: Option<i64>,
    #[serde(default)]
    actor_user_id: Option<i64>,
    #[serde(default)]
    key_packages: Option<Vec<String>>,
    #[serde(default)]
    welcome_b64: Option<String>,
    #[serde(default)]
    commit_b64: Option<String>,
    #[serde(default)]
    message_b64: Option<String>,
    #[serde(default)]
    plaintext_b64: Option<String>,
    #[serde(default)]
    user_ids: Option<Vec<i64>>,
    #[serde(default)]
    state_b64: Option<String>,
    #[serde(default)]
    public_state_b64: Option<String>,
    #[serde(default)]
    group_info_b64: Option<String>,
    #[serde(default)]
    ratchet_tree_b64: Option<String>,
    #[serde(default)]
    expected_member_ids: Option<Vec<i64>>,
}

impl Command {
    fn new(cmd: &str) -> Self {
        Self {
            cmd: cmd.to_string(),
            ..Self::default()
        }
    }
}

/// Tự kiểm: dựng Alice + Bob, tạo group, add Bob qua Welcome, mã hóa/giải mã một
/// tin và remove Bob — xác nhận toàn bộ vòng đời MLS chạy đúng trên máy hiện tại.
fn selftest() -> Result<Value, String> {
    let mut alice = BridgeState::default();
    let mut bob = BridgeState::default();

    let mut init_alice = Command::new("init_identity");
    init_alice.user_id = Some(1);
    init_alice.email = Some("123@gmail.com".into());
    init_alice.secchat_identity_pk = Some("alice-id".into());
    init_alice.secchat_identity_version = Some(1);
    alice.handle(init_alice)?;

    let mut init_bob = Command::new("init_identity");
    init_bob.user_id = Some(2);
    init_bob.email = Some("234@gmail.com".into());
    init_bob.secchat_identity_pk = Some("bob-id".into());
    init_bob.secchat_identity_version = Some(1);
    bob.handle(init_bob)?;

    let mut bob_kps_cmd = Command::new("top_up_key_packages");
    bob_kps_cmd.count = Some(1);
    let bob_kps = bob.handle(bob_kps_cmd)?;
    let bob_kp = bob_kps["key_packages"][0]["key_package_b64"]
        .as_str()
        .ok_or("selftest key package missing")?
        .to_string();

    let mut create_cmd = Command::new("create_group");
    create_cmd.conversation_id = Some(42);
    alice.handle(create_cmd)?;

    let mut add_cmd = Command::new("add_members");
    add_cmd.conversation_id = Some(42);
    add_cmd.key_packages = Some(vec![bob_kp]);
    let add = alice.handle(add_cmd)?;
    let welcome_b64 = add["welcome_b64"]
        .as_str()
        .ok_or("selftest welcome missing")?
        .to_string();

    let mut validate_create = Command::new("validate_group_create");
    validate_create.conversation_id = Some(42);
    validate_create.group_info_b64 = Some(
        add["group_info_b64"]
            .as_str()
            .ok_or("selftest add GroupInfo missing")?
            .to_string(),
    );
    validate_create.ratchet_tree_b64 = Some(
        add["ratchet_tree_b64"]
            .as_str()
            .ok_or("selftest add RatchetTree missing")?
            .to_string(),
    );
    validate_create.expected_member_ids = Some(vec![1, 2]);
    let public_create = BridgeState::default().handle(validate_create)?;
    let public_state_b64 = public_create["public_state_b64"]
        .as_str()
        .ok_or("selftest public state missing")?
        .to_string();

    let mut join_cmd = Command::new("join_from_welcome");
    join_cmd.conversation_id = Some(42);
    join_cmd.welcome_b64 = Some(welcome_b64);
    bob.handle(join_cmd)?;

    let plain = b"secchat mls app message";
    let mut app_cmd = Command::new("encrypt_application");
    app_cmd.conversation_id = Some(42);
    app_cmd.plaintext_b64 = Some(b64e(plain));
    let app = alice.handle(app_cmd)?;
    let message_b64 = app["message_b64"]
        .as_str()
        .ok_or("selftest app missing")?
        .to_string();

    let mut decrypt_cmd = Command::new("decrypt_application");
    decrypt_cmd.conversation_id = Some(42);
    decrypt_cmd.message_b64 = Some(message_b64);
    let decrypted = bob.handle(decrypt_cmd)?;
    let got = b64d(
        decrypted["plaintext_b64"]
            .as_str()
            .ok_or("selftest plaintext missing")?,
    )?;
    if got != plain {
        return Err("application plaintext mismatch".into());
    }

    let bob_snapshot = bob.handle(Command::new("export_state"))?;
    let bob_state_b64 = bob_snapshot["state_b64"]
        .as_str()
        .ok_or("selftest exported state missing")?
        .to_string();
    let mut bob_restored = BridgeState::default();
    let mut import_cmd = Command::new("import_state");
    import_cmd.state_b64 = Some(bob_state_b64);
    bob_restored.handle(import_cmd)?;

    let plain_after_restart = b"secchat mls app message after restart";
    let mut app_after_restart_cmd = Command::new("encrypt_application");
    app_after_restart_cmd.conversation_id = Some(42);
    app_after_restart_cmd.plaintext_b64 = Some(b64e(plain_after_restart));
    let app_after_restart = alice.handle(app_after_restart_cmd)?;
    let message_after_restart_b64 = app_after_restart["message_b64"]
        .as_str()
        .ok_or("selftest post-import app missing")?
        .to_string();

    let mut decrypt_after_restart_cmd = Command::new("decrypt_application");
    decrypt_after_restart_cmd.conversation_id = Some(42);
    decrypt_after_restart_cmd.message_b64 = Some(message_after_restart_b64);
    let decrypted_after_restart = bob_restored.handle(decrypt_after_restart_cmd)?;
    let got_after_restart = b64d(
        decrypted_after_restart["plaintext_b64"]
            .as_str()
            .ok_or("selftest post-import plaintext missing")?,
    )?;
    if got_after_restart != plain_after_restart {
        return Err("application plaintext mismatch after state import".into());
    }
    bob = bob_restored;

    let mut remove_cmd = Command::new("remove_members");
    remove_cmd.conversation_id = Some(42);
    remove_cmd.user_ids = Some(vec![2]);
    let remove = alice.handle(remove_cmd)?;
    let remove_commit = remove["commit_b64"]
        .as_str()
        .ok_or("selftest remove commit missing")?
        .to_string();

    let mut validate_remove = Command::new("validate_group_commit");
    validate_remove.conversation_id = Some(42);
    validate_remove.public_state_b64 = Some(public_state_b64);
    validate_remove.commit_b64 = Some(remove_commit.clone());
    validate_remove.group_info_b64 = Some(
        remove["group_info_b64"]
            .as_str()
            .ok_or("selftest remove GroupInfo missing")?
            .to_string(),
    );
    validate_remove.ratchet_tree_b64 = Some(
        remove["ratchet_tree_b64"]
            .as_str()
            .ok_or("selftest remove RatchetTree missing")?
            .to_string(),
    );
    validate_remove.actor_user_id = Some(1);
    validate_remove.expected_member_ids = Some(vec![1]);
    BridgeState::default().handle(validate_remove.clone())?;

    let mut bogus = validate_remove;
    bogus.commit_b64 = Some("AAAA".into());
    if BridgeState::default().handle(bogus).is_ok() {
        return Err("bogus public MLS commit unexpectedly validated".into());
    }

    let mut process_remove_cmd = Command::new("process_commit");
    process_remove_cmd.conversation_id = Some(42);
    process_remove_cmd.commit_b64 = Some(remove_commit);
    let processed_remove = bob.handle(process_remove_cmd)?;
    if processed_remove["active"].as_bool().unwrap_or(true) {
        return Err("removed member group remained active".into());
    }

    Ok(with_ciphersuite_metadata(json!({
        "ok": true,
        "add_commit_bytes": b64d(add["commit_b64"].as_str().unwrap_or(""))?.len(),
        "welcome_bytes": b64d(add["welcome_b64"].as_str().unwrap_or(""))?.len(),
        "app_bytes": b64d(app["message_b64"].as_str().unwrap_or(""))?.len(),
        "remove_commit_bytes": b64d(remove["commit_b64"].as_str().unwrap_or(""))?.len(),
        "validator_create_ok": true,
        "validator_remove_ok": true,
        "validator_rejects_bogus_commit": true,
        "bob_active_after_remove": false
    })))
}

/// In kết quả JSON ra stdout (luôn gắn field "ok") cho client Python đọc lại.
fn write_result(result: Result<Value, String>) {
    match result {
        Ok(mut value) => {
            if let Value::Object(ref mut obj) = value {
                obj.insert("ok".into(), Value::Bool(true));
            }
            println!("{value}");
        }
        Err(err) => {
            println!("{}", json!({"ok": false, "error": err}));
        }
    }
}

/// Vòng lặp phục vụ: đọc từng dòng JSON từ stdin, dispatch qua `handle`, in kết
/// quả. Giữ MỘT `BridgeState` xuyên suốt phiên (state group sống trong RAM).
fn serve() -> i32 {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut state = BridgeState::default();
    for line in stdin.lock().lines() {
        let line = match line {
            Ok(line) => line,
            Err(err) => {
                println!("{}", json!({"ok": false, "error": format!("stdin failed: {err}")}));
                let _ = stdout.flush();
                continue;
            }
        };
        if line.trim().is_empty() {
            continue;
        }
        let result = serde_json::from_str::<Command>(&line)
            .map_err(|err| format!("invalid command JSON: {err}"))
            .and_then(|cmd| state.handle(cmd));
        write_result(result);
        let _ = stdout.flush();
    }
    0
}

/// Chạy một lệnh đơn lẻ rồi thoát (dùng cho version/status/selftest).
fn one_shot(command: &str) -> i32 {
    let mut state = BridgeState::default();
    let result = match command {
        "version" | "status" => state.handle(Command::new(command)),
        "selftest" => selftest(),
        other => Err(format!("unknown command: {other}")),
    };
    let ok = result.is_ok();
    write_result(result);
    if ok { 0 } else { 1 }
}

/// Đọc một file JSON chứa lệnh validate rồi chạy một lần (tiện cho server/CI).
fn validate_file(path: &str) -> i32 {
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) => {
            write_result(Err(format!("validation file read failed: {err}")));
            return 1;
        }
    };
    let result = serde_json::from_str::<Command>(&text)
        .map_err(|err| format!("invalid validation JSON: {err}"))
        .and_then(|cmd| BridgeState::default().handle(cmd));
    let ok = result.is_ok();
    write_result(result);
    if ok { 0 } else { 1 }
}

/// Điểm vào: chọn chế độ theo tham số dòng lệnh (`serve` / `validate_file` / lệnh đơn).
fn main() {
    let mut args = std::env::args().skip(1);
    let command = args.next().unwrap_or_else(|| "selftest".to_string());
    let code = match command.as_str() {
        "serve" => serve(),
        "validate_file" => match args.next() {
            Some(path) => validate_file(&path),
            None => {
                write_result(Err("validate_file path missing".into()));
                1
            }
        },
        _ => one_shot(&command),
    };
    std::process::exit(code);
}
