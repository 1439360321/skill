char *get_config_value(const char *key) {
    Config *cfg = load_config();
    char *val = cfg->entries[key];
    return strdup(val);
}