#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "openssl"
require "socket"
require "timeout"
require "tmpdir"

def find_free_port(start_port = 26200)
  port = start_port
  loop do
    begin
      server = TCPServer.new("127.0.0.1", port)
      server.close
      return port
    rescue Errno::EADDRINUSE
      port += 1
    end
  end
end

def wait_for_start(log_path, timeout_secs = 5)
  Timeout.timeout(timeout_secs) do
    loop do
      if File.exist?(log_path) && File.read(log_path).include?("Started listener")
        return
      end

      sleep 0.05
    end
  end
end

repo_root = File.expand_path("../..", __dir__)
agate_bin = ENV.fetch("AGATE_BIN", File.join(repo_root, "target/debug/agate"))
idle_wait_secs = Integer(ENV.fetch("PROBE_IDLE_WAIT_SECS", "5"))

unless File.executable?(agate_bin)
  Dir.chdir(repo_root) { system("cargo", "build", out: File::NULL) } || abort("cargo build failed")
end

Dir.mktmpdir("agate-idle-timeout-") do |tmp_dir|
  content = File.join(tmp_dir, "content")
  certs = File.join(tmp_dir, "certs")
  log_path = File.join(tmp_dir, "server.log")
  FileUtils.mkdir_p(content)
  File.write(File.join(content, "index.gmi"), "home\n")

  port = find_free_port
  pid = spawn(
    agate_bin,
    "--addr", "127.0.0.1:#{port}",
    "--content", content,
    "--certs", certs,
    "--hostname", "localhost",
    out: File::NULL,
    err: log_path
  )

  begin
    wait_for_start(log_path)

    tcp = TCPSocket.new("127.0.0.1", port)
    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE
    tls = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
    tls.hostname = "localhost" if tls.respond_to?(:hostname=)
    tls.connect

    tls.write("gemini://localhost/index.gmi")
    sleep idle_wait_secs

    begin
      tls.write("\r\n")
      header = Timeout.timeout(2) { tls.gets.to_s }
      if header.start_with?("20 ")
        warn "VULNERABLE: connection stayed open after #{idle_wait_secs}s partial request."
        exit 1
      end
    rescue IOError, Errno::EPIPE, OpenSSL::SSL::SSLError, EOFError, Timeout::Error
      # If write/read fails after idle period, timeout/close behavior exists.
    end

    puts "PASS: partial request was not kept alive beyond idle window."
    exit 0
  ensure
    begin
      tls&.close
    rescue StandardError
      nil
    end
    begin
      tcp&.close
    rescue StandardError
      nil
    end
    Process.kill("TERM", pid) rescue nil
    Process.wait(pid) rescue nil
  end
end
