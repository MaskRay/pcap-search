#!/usr/bin/env ruby

require 'json'
require 'socket'
require 'tempfile'
require 'timeout'
begin
  require 'tilt'
  require 'sass'
  require 'slim'
  require 'coffee-script'
  require 'sinatra'
  require 'sinatra/reloader'
rescue LoadError => e
  STDERR.puts e.message
  STDERR.puts 'gem install sinatra sinatra-contrib tilt sass slim coffee-script'
  exit 1
end

SEARCH_SOCK = '/tmp/search.sock'
FLOW_SOCK = '/tmp/flow.sock'
SEARCH_TIMEOUT = 30
MAX_PAGES = 30
PER_PAGE = 20
PCAP_DIR = File.expand_path '/tmp/pcap'

# Main

configure :development do
  register Sinatra::Reloader
end

set :static, true
set :public_folder, File.join(__dir__, "static")
set :views, __dir__
set :bind, '0'
set :port, 4568

set :views, sass: 'css', coffee: 'js', :default => 'html'

helpers do
  def find_template(views, name, engine, &block)
    _, folder = views.detect { |k,v| engine == Tilt[k] }
    folder ||= views[:default]
    super(folder, name, engine, &block)
  end
end

before do
  response.headers['Access-Control-Allow-Origin'] = '*'
end

get '/' do
  send_file File.join(__dir__,'static','index.html')
end

get '/download' do
  query = Rack::Utils.parse_query request.query_string
  filename = query['filename']
  offset = query['offset']
  type = query['type']
  service = query['service'] || 'all'
  unless filename && type
    return 412
  end
  case type
  when 'all'
    content_type 'application/vnd.tcpdump.pcap'
    attachment filename
    send_file File.join(PCAP_DIR, service, filename)
  when 'pcap', 'str', 'hex', 'repr', 'pythonsimple', 'pythondiff'
    return 412 unless offset
    if type == 'pcap'
      content_type 'application/vnd.tcpdump.pcap'
      attachment "#{filename.sub(/\.cap$/, '')}@#{offset}.cap"
    end
    temp_file = Tempfile.new filename
    offset2stream File.join(PCAP_DIR, service, filename), offset, type, temp_file.path do |h|
      h.read
    end
    Thread.new do
      sleep 1
      path = temp_file.path
      temp_file.close
      File.delete path
    end
    send_file temp_file
  else
    412
  end
end

get '/api/list' do
  content_type :json
  Dir.entries(PCAP_DIR).select {|x| x !~ /^\./ && File.directory?(File.join PCAP_DIR, x) }.to_json
end

get '/api/autocomplete' do
  content_type :json
  query = Rack::Utils.parse_query request.query_string
  q = query['q'] || ''
  service = query['service'] || 'all'
  res = ''
  begin
    Timeout.timeout SEARCH_TIMEOUT do
      sock = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
      sock.connect Socket.pack_sockaddr_un(SEARCH_SOCK)
      sock.write "\0#{File.join PCAP_DIR, service, "\x01"}\0#{File.join PCAP_DIR, service, "\x7f"}\0#{q}"
      sock.close_write
      sug = []
      sock.read.lines.each {|line|
        filepath, offset, context = line.chomp.split "\t"
        filepath = filepath.sub(/\.ap$/, '')
        offset = offset.to_i
        offset2stream filepath, offset, 'loc', '/dev/stdout' do |h|
          _, y = h.read.split.map(&:to_i)
          sug << context.scan(/(?:\\x(?:..)|[^\\]){,#{[y-offset,context.size].min}}/)[0] if offset < y
        end
      }
      res = {query: q, suggestions: sug.uniq }.to_json
      sock.close
    end
  rescue => e
    STDERR.puts e.message
    STDERR.puts e.backtrace
  end
  res
end

get '/api/search' do
  query = Rack::Utils.parse_query request.query_string
  q = query['q'] || ''
  service = query['service'] || 'all'
  page = (query['page'] || 0).to_i
  offset = page*PER_PAGE
  res = ''
  total = 0

  begin
    Timeout.timeout SEARCH_TIMEOUT do
      sock = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
      sock.connect Socket.pack_sockaddr_un(SEARCH_SOCK)
      sock.write "#{offset}\0#{File.join PCAP_DIR, service, "\x01"}\0#{File.join PCAP_DIR, service, "\x7f"}\0#{q}"
      sock.close_write
      lines = sock.read.lines
      sock.close
      total = [lines[-1].to_i, PER_PAGE*MAX_PAGES].min

      res = []
      lines[0...-1].each {|line|
        filepath, offset, len = line.chomp.split "\t"
        begin
          sock2 = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
          sock2.connect Socket.pack_sockaddr_un(FLOW_SOCK)
          sock2.write "#{filepath}\0#{offset}\0#{len}"
          sock2.close_write
          epoch, client_port, server_port, context = sock2.read.split "\t"
          res << {filename: filepath.sub(/.*\/(.*)\.ap$/, '\1'), offset: offset.to_i, epoch: epoch.to_i, port0: server_port.to_i, port1: client_port.to_i, context: context}
        rescue
        end
      }
      #puts "++ res"
      #puts lines, res

      res_grouped = Hash.new {|h,k| h[k] = [] }
      res.each {|x|
        filename = x.delete :filename
        res_grouped[filename] << x
      }

      res = {
        query: q,
        results: res_grouped
      }.to_json
    end
  rescue Timeout::Error => e
    STDERR.puts e.message
  rescue => e
    STDERR.puts e.message
    STDERR.puts e.backtrace
  else
    res
  end
end
