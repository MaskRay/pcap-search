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
SEARCH_TIMEOUT = 30
MAX_PAGES = 30
PER_PAGE = 20
DSHELL_DEFCON = File.join __dir__, '..', 'dshell-defcon'
PCAP_DIR = File.expand_path '/tmp/n'

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
  unless filename && type
    return 412
  end
  case type
  when 'all'
    content_type 'application/vnd.tcpdump.pcap'
    attachment filename
    send_file File.join(PCAP_DIR, filename)
  when 'pcap', 'str', 'hex', 'repr', 'python'
    return 412 unless offset
    if type == 'pcap'
      content_type 'application/vnd.tcpdump.pcap'
      attachment "#{filename.sub(/\.cap$/, '')}@#{offset}.cap"
    end
    temp_file = Tempfile.new filename
    offset2stream filename, offset, type, temp_file.path do |h|
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

def offset2stream filepath, offset, type, out, &block
  IO.popen([File.join(DSHELL_DEFCON, 'offset2stream.py'), "#{filepath}.ap", offset.to_s, type, filepath, out], &block)
end

get '/api/list' do
  content_type :json
  Dir.entries(PCAP_DIR).select {|x| x !~ /^\./ && File.directory?(File.join PCAP_DIR, x) }.to_json
end

get '/api/autocomplete' do
  content_type :json
  query = Rack::Utils.parse_query request.query_string
  q = query['q'] || ''
  res = ''
  begin
    Timeout.timeout SEARCH_TIMEOUT do
      sock = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
      sock.connect Socket.pack_sockaddr_un(SEARCH_SOCK)
      sock.write "\0#{File.join PCAP_DIR, 'all'}\0#{File.join PCAP_DIR, 'all'}\0#{q}"
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

  qq = q.gsub(/\\[0-7]{1,3}/) {|match|
    "\\x#{'%02x' % match[1..-1].to_i(8)}"
  }
  .gsub('\\\\', '\\x5c')
  .gsub('\\a', '\\x07')
  .gsub('\\b', '\\x08')
  .gsub('\\t', '\\x09')
  .gsub('\\n', '\\x0a')
  .gsub('\\v', '\\x0b')
  .gsub('\\f', '\\x0c')
  .gsub('\\r', '\\x0d')

  begin
    Timeout.timeout SEARCH_TIMEOUT do
      sock = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
      sock.connect Socket.pack_sockaddr_un(SEARCH_SOCK)
      sock.write "#{offset}\0#{File.join PCAP_DIR, service, "\x01"}\0#{File.join PCAP_DIR, service, "\x7f"}\0#{qq}"
      sock.close_write
      lines = sock.read.lines
      sock.close
      total = [lines[-1].to_i, PER_PAGE*MAX_PAGES].min

      res = []
      IO.popen [File.join(DSHELL_DEFCON, 'context.py')], 'r+' do |h|
        lines[0...-1].each {|line|
          filepath, offset, len = line.chomp.split "\t"
          h.puts "#{filepath}\t#{offset}\t#{len}"
          h.flush
          line = h.readline
          _, offset, epoch, port0, port1, context = line.chomp.split "\t"
          epoch = epoch.to_i
          if epoch >= 0 && context && ! context.empty?
            res << {filename: filepath.sub(/.*\/(.*)\.ap$/, '\1'), offset: offset.to_i, epoch: epoch, port0: port0.to_i, port1: port1.to_i, context: context}
          end
        }
      end

      res_grouped = Hash.new {|h,k| h[k] = [] }
      res.each {|x|
        filename = x.delete :filename
        res_grouped[filename] << x
      }

      res = {
        query: qq,
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
