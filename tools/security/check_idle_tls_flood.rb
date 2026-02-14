#!/usr/bin/env ruby
# frozen_string_literal: true

require "fileutils"
require "openssl"
require "socket"
require "timeout"
require "tmpdir"

def find_free_port(start_port = 26250)
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
conn_count = Integer(ENV.fetch("PROBE_IDLE_CONN_COUNT", "160"))

unless File.executable?(agate_bin)
  Dir.chdir(repo_root) { system("cargo", "build", out: File::NULL) } || abort("cargo build failed")
end

Dir.mktmpdir("agate-idle-flood-") do |tmp_dir|
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

  sockets = []
  successful = 0

  begin
    wait_for_start(log_path)

    ctx = OpenSSL::SSL::SSLContext.new
    ctx.verify_mode = OpenSSL::SSL::VERIFY_NONE

    conn_count.times do
      begin
        tcp = TCPSocket.new("127.0.0.1", port)
        tls = OpenSSL::SSL::SSLSocket.new(tcp, ctx)
        tls.hostname = "localhost" if tls.respond_to?(:hostname=)
        tls.connect
        sockets << [tls, tcp]
        successful += 1
      rescue StandardError
        break
      end
    end

    sleep 2

    if successful >= conn_count
      warn "VULNERABLE: accepted #{successful} idle TLS sessions without visible cap."
      exit 1
    end

    puts "PASS: idle TLS sessions were capped before #{conn_count}."
    exit 0
  ensure
    sockets.each do |tls, tcp|
      begin
        tls.close
      rescue StandardError
        nil
      end
      begin
        tcp.close
      rescue StandardError
        nil
      end
    end
    Process.kill("TERM", pid) rescue nil
    Process.wait(pid) rescue nil
  end
end
