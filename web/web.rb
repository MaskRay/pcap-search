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
set :public_folder, __dir__
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
  send_file 'html/index.html'
end

get '/download' do
  query = Rack::Utils.parse_query request.query_string
  filename = query['filename']
  offset = query['offset']
  format = query['format']
  unless filename && format
    return 412
  end
  case format
  when 'all'
    send_file File.join(PCAP_DIR, filename)
  when 'pcap', 'str', 'hex', 'repr'
    return 412 unless offset
    temp_file = Tempfile.new filename
    IO.popen [File.join(DSHELL_DEFCON, './offset2stream.py'), File.join(PCAP_DIR, "#{filename}.ap"), offset, format, File.join(PCAP_DIR, filename), temp_file.path] do |h|
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

get '/api/autocomplete' do
  content_type :json
  query = Rack::Utils.parse_query request.query_string
  q = query['q'] || ''
  res = ''
  begin
    Timeout.timeout SEARCH_TIMEOUT do
      sock = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
      sock.connect Socket.pack_sockaddr_un(SEARCH_SOCK)
      sock.write "\0\0\0#{q}"
      sock.close_write
      res = {query: q, suggestions: sock.read.lines.map(&:chomp) }.to_json
      sock.close
    end
  rescue
  end
  res
end

get '/api/search' do
  query = Rack::Utils.parse_query request.query_string
  q = query['q'] || ''
  page = (query['page'] || 0).to_i
  offset = page*PER_PAGE
  res = ''
  total = 0

  begin
    Timeout.timeout SEARCH_TIMEOUT do
      sock = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
      sock.connect Socket.pack_sockaddr_un(SEARCH_SOCK)
      sock.write "#{offset}\0\0\0#{q}"
      sock.close_write
      lines = sock.read.lines
      sock.close
      total = [lines[-1].to_i, PER_PAGE*MAX_PAGES].min
      qq = q.gsub(/\\[0-7]{1,3}/) {|match|
        "\\x#{'%02x' % match[1..-1].to_i(8)}"
      }
      .gsub('\\a', '\\x07')
      .gsub('\\b', '\\x08')
      .gsub('\\t', '\\x09')
      .gsub('\\n', '\\x0a')
      .gsub('\\v', '\\x0b')
      .gsub('\\f', '\\x0c')
      .gsub('\\r', '\\x0d')
      .gsub('\\', '\\x5c')

      res = lines[0..-2].map {|line|
        filename, offset, context = line.chomp.split "\t"
        {filename: filename, offset: offset, context: context}
      }
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
  rescue Timeout::Error
  rescue => e
    STDERR.puts e.message
    STDERR.puts e.backtrace
  end
  res
end

get '/search' do
  query = Rack::Utils.parse_query request.query_string
  q = query['q'] || ''
  page = (query['page'] || 0).to_i
  offset = page*PER_PAGE
  result = []
  total = 0

  begin
    Timeout.timeout SEARCH_TIMEOUT do
      sock = Socket.new Socket::AF_UNIX, Socket::SOCK_STREAM, 0
      sock.connect Socket.pack_sockaddr_un(SEARCH_SOCK)
      sock.write "#{offset}\0\0\0#{q}"
      sock.close_write
      lines = sock.read.lines
      sock.close
      total = [lines[-1].to_i, PER_PAGE*MAX_PAGES].min
      qq = q.gsub(/\\[0-7]{1,3}/) {|match|
        "\\x#{'%02x' % match[1..-1].to_i(8)}"
      }
      .gsub('\\a', '\\x07')
      .gsub('\\b', '\\x08')
      .gsub('\\t', '\\x09')
      .gsub('\\n', '\\x0a')
      .gsub('\\v', '\\x0b')
      .gsub('\\f', '\\x0c')
      .gsub('\\r', '\\x0d')
      p q, qq
      result = lines[0..-2].map {|line|
        filename, offset, context = line.split "\t"
        offset = offset.to_i
        context.gsub!(qq) {|match|
          "<span class=red>#{match}</span>"
        }

        context.gsub!(/\\x[[:xdigit:]]{2}/) {|match|
          "<span class=hex>#{match[2..-1]}</span>"
        }

        {offset: offset, len: q.size, uri: '#', filename: filename, context: context}
      }
    end
  rescue Timeout::Error
  rescue => e
    STDERR.puts e.message
    STDERR.puts e.backtrace
  end
  slim :search, locals: {result: result, pages: (total+PER_PAGE-1)/PER_PAGE, page: page, q: q}
end
