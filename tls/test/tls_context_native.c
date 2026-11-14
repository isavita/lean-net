/* Real allocator ownership check for borrowed certificate-table arrays. */
#include "../c/tls_worker.c"
#include <stdio.h>

void lean_initialize_runtime_module(void);
static void check(int condition, const char *message) {
  if (!condition) { fprintf(stderr,"TLS context native: %s\n",message); exit(1); }
}
static lean_object *strings(const char *const *values, size_t count) {
  lean_object *array=lean_alloc_array(count,count);
  for(size_t i=0;i<count;++i) lean_array_set_core(array,i,lean_mk_string(values[i]));
  return array;
}
static void exclusive(lean_object *array) {
  for(size_t i=0;i<lean_array_size(array);++i)
    check(lean_is_exclusive(lean_array_uget_borrowed(array,i)),"borrowed table element leaked a reference");
}
static void table_case(const char *certificate,const char *private_key,
    const char *const *hosts,size_t count,int bad_certificate,int success,uint8_t tickets) {
  const char *certificates[TW_MAX_CERTS],*keys[TW_MAX_CERTS];
  for(size_t i=0;i<count;++i){certificates[i]=bad_certificate && i+1==count ? "/missing/lean-net-native-cert.pem" : certificate;keys[i]=private_key;}
  lean_object *names=strings(hosts,count),*certs=strings(certificates,count),*secrets=strings(keys,count);
  lean_object *cert=lean_mk_string(certificate),*key=lean_mk_string(private_key);
  exclusive(names);exclusive(certs);exclusive(secrets);
  lean_object *result=lean_tlsw_bundle_new(cert,key,names,certs,secrets,tickets);
  check(lean_io_result_is_ok(result),"context setup returns IO result");
  int64_t value=(int64_t)lean_unbox_uint64(lean_ctor_get(lean_io_result_get_value(result),0));
  exclusive(names);exclusive(certs);exclusive(secrets);
  check(lean_is_exclusive(cert) && lean_is_exclusive(key),"default borrowed paths retain exactly caller ownership");
  check(success ? value>0 : value<0,"certificate table setup outcome");
  if(success){
    tw_bundle *bundle=(tw_bundle *)(uintptr_t)value;
    for(uint32_t i=0;i<bundle->count;++i){
      SSL_CTX *context=bundle->contexts[i].ssl;
      check(SSL_CTX_get_min_proto_version(context)==TLS1_2_VERSION,"TLS 1.2 minimum retained");
      check((SSL_CTX_get_options(context)&SSL_OP_CIPHER_SERVER_PREFERENCE)!=0,"server cipher preference enabled");
      check((SSL_CTX_get_session_cache_mode(context)&SSL_SESS_CACHE_SERVER)!=0,"server session cache enabled");
      check(SSL_CTX_get_num_tickets(context)==(tickets?2u:0u),"configured TLS 1.3 ticket count");
    }
    lean_object *released=lean_tlsw_bundle_free((uint64_t)value);
    check(lean_io_result_is_ok(released) && lean_unbox_uint64(lean_io_result_get_value(released))==0,"free context bundle");lean_dec(released);
  }
  lean_dec(result);lean_dec(key);lean_dec(cert);lean_dec(secrets);lean_dec(certs);lean_dec(names);
}
int main(int argc,char **argv){
  check(argc==3,"certificate and key arguments required");lean_initialize_runtime_module();
  tw_bundle *partial=calloc(1,sizeof(*partial));check(partial!=NULL,"allocate partial bundle fixture");
  atomic_init(&partial->references,1);partial->count=2;tw_bundle_release(partial);
  const char *valid[]={"alpha.test","beta.test"};
  const char *duplicate[]={"ALPHA.test","alpha.test"};
  const char *invalid[]={"bad name"};
  table_case(argv[1],argv[2],valid,2,0,1,1);
  table_case(argv[1],argv[2],valid,2,0,1,0);
  table_case(argv[1],argv[2],duplicate,2,0,0,1);
  table_case(argv[1],argv[2],invalid,1,0,0,1);
  table_case(argv[1],argv[2],valid,2,1,0,1);
  puts("TLS context borrowed ownership and policy checks passed");return 0;
}
