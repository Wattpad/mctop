require 'pcap'
require 'thread'

done = false

%w[ INT QUIT HUP KILL ].each do |sig|
  Signal.trap(sig) do
    puts "** Caught signal #{sig} - exiting"
    done = true
  end
end

t = Thread.new {
  cap = Pcap::Capture.open_live(@source, 1500)
  cap.setfilter("port 11211")
  cap.loop do |packet|
    # parse key name, and size from VALUE responses
    if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
      puts packet.raw_data
    end
    break if done
  end
  cap.close
}
