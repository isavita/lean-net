/* Shared capability wrappers. Backend-local implementations remain available
 * to native completion/error cleanup without granting plaintext aliases access. */
int rn_queue_write(rn_reactor *r, uint64_t t, uint64_t b, uint32_t o, uint32_t n, uint64_t op) {
    int e = rn_transport_access(r,t,0,1); return e ? e : rn_queue_write_impl(r,t,b,o,n,op);
}
int rn_set_read_enabled(rn_reactor *r, uint64_t t, int enabled) {
    int e = rn_transport_access(r,t,0,1); return e ? e : rn_set_read_enabled_impl(r,t,enabled);
}
int rn_arm_timer(rn_reactor *r, uint64_t t, uint32_t k, uint64_t deadline) {
    int e = rn_transport_access(r,t,0,1); return e ? e : rn_arm_timer_impl(r,t,k,deadline);
}
int rn_cancel_timer(rn_reactor *r, uint64_t t, uint32_t k) {
    int e = rn_transport_access(r,t,0,1); return e ? e : rn_cancel_timer_impl(r,t,k);
}
int rn_close_after_writes(rn_reactor *r, uint64_t t) {
    int e = rn_transport_access(r,t,0,1); return e ? e : rn_close_after_writes_impl(r,t);
}
int rn_close_connection(rn_reactor *r, uint64_t t) {
    int e = rn_transport_access(r,t,0,1); return e ? e : rn_close_connection_impl(r,t);
}
int rn_transport_write(rn_reactor *r, uint64_t t, uint64_t c, uint64_t b, uint32_t o, uint32_t n, uint64_t op) {
    int e = rn_transport_access(r,t,c,0); return e ? e : rn_queue_write_impl(r,t,b,o,n,op);
}
int rn_transport_read_enabled(rn_reactor *r, uint64_t t, uint64_t c, int enabled) {
    int e = rn_transport_access(r,t,c,0); return e ? e : rn_set_read_enabled_impl(r,t,enabled);
}
int rn_transport_arm_timer(rn_reactor *r, uint64_t t, uint64_t c, uint32_t k, uint64_t deadline) {
    int e = rn_transport_access(r,t,c,0); return e ? e : rn_arm_timer_impl(r,t,k,deadline);
}
int rn_transport_cancel_timer(rn_reactor *r, uint64_t t, uint64_t c, uint32_t k) {
    int e = rn_transport_access(r,t,c,0); return e ? e : rn_cancel_timer_impl(r,t,k);
}
int rn_transport_drain(rn_reactor *r, uint64_t t, uint64_t c) {
    int e = rn_transport_access(r,t,c,0); return e ? e : rn_close_after_writes_impl(r,t);
}
int rn_transport_abort(rn_reactor *r, uint64_t t, uint64_t c) {
    int e = rn_transport_access(r,t,c,0); return e ? e : rn_close_connection_impl(r,t);
}
