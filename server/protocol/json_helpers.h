#ifndef SECCHAT_PROTOCOL_JSON_HELPERS_H
#define SECCHAT_PROTOCOL_JSON_HELPERS_H

/* Parse a string value: "key":"value"  → copies value into val[vmax].
   Returns 1 on success, 0 if key not found or value is not a string. */
int  jget(const char *json, const char *key, char *val, int vmax);

/* Parse an integer value: "key":123  or  "key":"123"
   Returns 1 on success, 0 if key not found. */
int  jget_int(const char *json, const char *key, int *out_val);

/* Parse a JSON integer array: "key":[1,2,3]
   Returns number of elements parsed (up to maxlen). */
int  jget_array(const char *json, const char *key, int *arr, int maxlen);

/* Escape `in` for embedding in a JSON string (escapes " and \).
   Writes into out[maxout]. */
void json_esc(const char *in, char *out, int maxout);

#endif /* SECCHAT_PROTOCOL_JSON_HELPERS_H */
