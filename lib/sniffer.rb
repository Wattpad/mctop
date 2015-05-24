require 'pcap'
require 'thread'

class MemcacheSniffer

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]
    @host    = config[:host]

    @discard_thresh = config[:discard_thresh]

    @metrics = {}
    @packet_stats = { :recv => 0, :drop => 0 }

    @semaphore = Mutex.new
  end

  def start
    cap = Pcap::Capture.open_live(@source, 1500)

    @start_time = Time.new.to_f
    @done    = false

    if @host == ""
      cap.setfilter("port #{@port}")
    else
      cap.setfilter("host #{@host} and port #{@port}")
    end

    cap.loop do |packet|
      @packet_stats = cap.stats

      # parse key name, and size from VALUE responses
      if packet.raw_data =~ /VALUE (\S+) \S+ (\S+)/
        key   = $1
        bytes = $2

        @semaphore.synchronize do
          @metrics[key] = { key: key, calls: 0 } unless @metrics.has_key? key
          @metrics[key][:calls] += 1
          @metrics[key][:objsize] = bytes.to_i
        end
      end

      break if @done
    end

    cap.close
  end

  def packet_stats
    @packet_stats
  end

  def metrics
    @semaphore.synchronize do
      # we may have seen no packets received on the sniffer thread
      return {} if @start_time.nil?

      elapsed = Time.now.to_f - @start_time

      # iterate over all the keys in the metrics hash and calculate some values
      @metrics.each    { |k,v| v[:reqsec] = v[:calls] / elapsed }
              .keep_if { |k,v| v[:reqsec] > @discard_thresh }
              .each    { |k,v| v[:bw] = ((v[:objsize] * v[:reqsec]) * 8) / 1000 }
    end
    {}.merge(@metrics)
  end

  def done
    @done = true
  end
end
