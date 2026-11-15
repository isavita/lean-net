require 'time'

# Rack /binary endpoint served by pinned Puma in compare_http1.py.
BODY = "\x00\xff\r\nA".b.freeze
HEADERS = {
  'content-type' => 'application/octet-stream',
  'content-length' => '5',
  'x-content-type-options' => 'nosniff',
  'x-frame-options' => 'SAMEORIGIN',
  'content-security-policy' => "default-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
  'referrer-policy' => 'strict-origin-when-cross-origin'
}.freeze
DATE_LOCK = Mutex.new
@date_second = nil
@date_value = nil

def cached_date
  now = Time.now
  second = now.to_i
  return @date_value if second == @date_second
  DATE_LOCK.synchronize do
    if second != @date_second
      @date_value = now.httpdate
      @date_second = second
    end
    @date_value
  end
end

run ->(env) {
  if env['REQUEST_METHOD'] == 'GET' && env['PATH_INFO'] == '/binary'
    [200, HEADERS.merge('date' => cached_date), [BODY]]
  else
    [404, { 'content-length' => '0' }, []]
  end
}
