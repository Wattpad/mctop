require 'pcap'
require 'thread'

class MemcacheSniffer

  def initialize(config)
    @source  = config[:nic]
    @port    = config[:port]
    @host    = config[:host]

    @discard_thresh = config[:discard_thresh]

    @metrics = {}
    @metrics[:calls]   = {}
    @metrics[:objsize] = {}
    @metrics[:reqsec]  = {}
    @metrics[:bw]    = {}

    @packet_stats = { :recv => 0, :drop => 0 }

    @semaphore = Mutex.new
  end

  def start
    cap = Pcap::Capture.open_live(@source, 1500)

    @metrics[:start_time] = Time.new.to_f
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
          if @metrics[:calls].has_key?(key)
            @metrics[:calls][key] += 1
          else
            @metrics[:calls][key] = 1
          end

          @metrics[:objsize][key] = bytes.to_i
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
      next if @metrics[:start_time].nil?
      # we may have seen no packets received on the sniffer thread
      elapsed = Time.now.to_f - @metrics[:start_time]

      # iterate over all the keys in the metrics hash and calculate some values
      @metrics[:calls].each do |k,v|
        reqsec = v / elapsed

        # if req/sec is <= the discard threshold delete those keys from
        # the metrics hash - this is a hack to manage the size of the
        # metrics hash in high volume environments
        if reqsec <= @discard_thresh
          @metrics[:calls].delete(k)
          @metrics[:objsize].delete(k)
          @metrics[:reqsec].delete(k)
          @metrics[:bw].delete(k)
        else
          @metrics[:reqsec][k]  = v / elapsed
          @metrics[:bw][k]    = ((@metrics[:objsize][k] * @metrics[:reqsec][k]) * 8) / 1000
        end
      end
    end
    @metrics.dup
  end

  def done
    @done = true
  end
end
