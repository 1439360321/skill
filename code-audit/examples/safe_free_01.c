void cleanup_resources_safe(Resource *res) {
    if (!res) return;
    if (res->data) {
        free(res->data);
        res->data = NULL;
    }
    free(res);
}