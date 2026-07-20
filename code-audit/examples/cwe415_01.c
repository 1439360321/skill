void cleanup_resources(Resource *res) {
    if (res->data) {
        free(res->data);
    }
    free(res->data);
    free(res);
}