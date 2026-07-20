char *get_config_value_safe(const char *key) {
    if (!key) return NULL;
    Config *cfg = load_config();
    if (!cfg || !cfg->entries) return NULL;
    char *val = cfg->entries[key];
    if (!val) return NULL;
    return strdup(val);
}