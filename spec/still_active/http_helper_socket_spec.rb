# frozen_string_literal: true

require "socket"
require "openssl"

# Connection reuse against a real TLS server, since WebMock never closes a socket:
# a pooled connection the server closed must not fail the next request, and a POST
# gets no retry from Net::HTTP to hide it.
RSpec.describe(StillActive::HttpHelper) do
  let(:servers) { [] }

  # mode: :keepalive (serves many), :close (sends Connection: close), :idle (closes after 0.5s idle)
  def serve(mode)
    key = OpenSSL::PKey::RSA.new(2048)
    cert = OpenSSL::X509::Certificate.new
    cert.version = 2
    cert.serial = 1
    cert.subject = cert.issuer = OpenSSL::X509::Name.parse("/CN=localhost")
    cert.public_key = key.public_key
    cert.not_before = Time.now - 60
    cert.not_after = Time.now + 600
    cert.sign(key, OpenSSL::Digest.new("SHA256"))
    context = OpenSSL::SSL::SSLContext.new
    context.cert = cert
    context.key = key
    tcp = TCPServer.new("127.0.0.1", 0)
    ssl = OpenSSL::SSL::SSLServer.new(tcp, context)
    server = Struct.new(:base, :tcp, :thread, :connections).new(URI("https://localhost:#{tcp.addr[1]}"), tcp, nil, 0)
    server.thread = Thread.new do
      loop do
        socket = ssl.accept
        server.connections += 1
        Thread.new(socket) { |client| answer(client, mode) }
      rescue OpenSSL::SSL::SSLError, IOError
        break if tcp.closed?
      end
    end
    servers << server
    server
  end

  def answer(client, mode)
    loop do
      break unless client.to_io.wait_readable((mode == :idle) ? 0.5 : 10)

      break unless client.gets
      length = 0
      while (line = client.gets) && line != "\r\n"
        length = line.split(":", 2)[1].to_i if line.match?(/\Acontent-length/i)
      end
      client.read(length) if length.positive?
      close_header = (mode == :close) ? "Connection: close\r\n" : ""
      client.write("HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n#{close_header}\r\n{}")
      break if mode == :close
    end
  ensure
    client.close
  end

  around do |example|
    WebMock.disable!
    example.run
  ensure
    WebMock.enable!
    servers.each do |server|
      server.tcp.close
      server.thread.kill
    end
  end

  # The throwaway certificate isn't trusted; relax verification for this example only.
  before do
    allow_any_instance_of(Net::HTTP).to(receive(:start).and_wrap_original { |original, *args| # rubocop:disable RSpec/AnyInstance
      original.receiver.verify_mode = OpenSSL::SSL::VERIFY_NONE
      original.call(*args)
    })
  end

  it("reuses one connection across GETs and POSTs to a keep-alive server") do
    server = serve(:keepalive)

    3.times { expect(described_class.post_json(server.base, "/q", body: "{}", strict: true)).to(eq({})) }
    expect(described_class.get_json(server.base, "/g", strict: true)).to(eq({}))

    expect(server.connections).to(eq(1))
  end

  it("opens a fresh connection when the server said Connection: close, so POSTs keep working") do
    server = serve(:close)

    3.times { expect(described_class.post_json(server.base, "/q", body: "{}", strict: true)).to(eq({})) }
  end

  # Both of Net::HTTP's checks: a socket the server closed (inside its 2s
  # keep-alive timeout), and one idle past that timeout.
  it("opens a fresh connection when the server closed an idle one, so a POST keeps working") do
    server = serve(:idle)

    expect(described_class.post_json(server.base, "/q", body: "{}", strict: true)).to(eq({}))
    sleep(1)
    expect(described_class.post_json(server.base, "/q", body: "{}", strict: true)).to(eq({}))
    sleep(2.2)
    expect(described_class.post_json(server.base, "/q", body: "{}", strict: true)).to(eq({}))
    expect(server.connections).to(eq(3))
  end
end
