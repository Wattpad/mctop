require 'pcap'
require 'thread'

done = false

%w[ INT QUIT HUP ].each do |sig|
  Signal.trap(sig) do
    puts "** Caught signal #{sig} - exiting"
    done = true
  end
end

t = Thread.new {
  cap = Pcap::Capture.open_live("eth0", 1500)
  cap.setfilter("port 11211")
  cap.loop do |packet|
    # parse key name, and size from VALUE responses
    if packet.raw_data =~ /set (\S+) (\d+) (\d+) (\d+)\r\n/
      puts packet.raw_data
    end
    break if done
  end
  cap.close
}

t.join
