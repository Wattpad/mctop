require 'optparse'
require 'pcap'

class CmdLine
  def self.parse(args)
    @config = {}

    opts = OptionParser.new do |opt|
      opt.on('-i', '--interface=NIC', 'Network interface to sniff (required)') do |nic|
        @config[:nic] = nic
      end

      @config[:host] = ''
      opt.on('--host=HOST', 'Network host to sniff on (default all)') do |host|
        @config[:host] = host
      end

      @config[:port] = 11211
      opt.on('-p', '--port=PORT', 'Network port to sniff on (default 11211)') do |port|
        @config[:port] = port
      end

      @config[:discard_thresh] = 0
      opt.on '-d', '--discard=THRESH', Float, 'Discard keys with request/sec rate below THRESH' do |discard_thresh|
        @config[:discard_thresh] = discard_thresh
      end

      @config[:refresh_rate] = 500
      opt.on '-r', '--refresh=MS', Float, 'Refresh the stats display every MS milliseconds' do |refresh_rate|
        @config[:refresh_rate] = refresh_rate
      end

      @config[:json_output] = false
      opt.on '-j', '--json-output', 'Output json array of top keys' do |json_output|
        @config[:json_output] = json_output
      end

      opt.separator ""
      opt.separator "In json-output mode:"

      @config[:capture_time] = 5
      opt.on '-t', '--capture-time=S', Integer, "In json-output mode: amount of time in S spent collecting stats (default: #{@config[:capture_time]})" do |capture_time|
        @config[:capture_time] = capture_time
      end

      @config[:sort_mode] = :reqseq
      opt.on '-s', '--sort-by=METRIC', [:reqsec, :objsize, :bw],
             "Metric to sort by.  Options: reqsec, objsize, bw (default: #{@config[:sort_mode]})" do |sort_mode|
        @config[:sort_mode] = sort_mode 
      end

      opt.separator ""

      opt.on_tail '-h', '--help', 'Show usage info' do
        puts opts
        exit
      end
    end

    opts.parse!

    # bail if we're not root
    unless Process::Sys.getuid == 0
      puts "** ERROR: needs to run as root to capture packets"
      exit 1
    end

    # we need need a nic to listen on
    unless @config.has_key?(:nic)
      puts "** ERROR: You must specify a network interface to listen on"
      puts opts
      exit 1
    end

    # we can't do 'any' interface just yet due to weirdness with ruby pcap libs
    if @config[:nic] =~ /any/i
      puts "** ERROR: can't bind to any interface due to odd issues with ruby-pcap"
      puts opts
      exit 1
    end

    @config
  end
end
