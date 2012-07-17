module Scanny
  module Checks
    class HTTPRequestCheck < Check
      def pattern
        [
          pattern_net_http,
          pattern_net_http_proxy
        ].join("|")
      end

      def check(node)
        issue :low, warning_message, :cwe => 441
      end

      private

      def warning_message
        "Connecting to the server without encryption" +
        "can facilitate sniffing traffic"
      end

      # Net::HTTP.new
      def pattern_net_http
        <<-EOT
          SendWithArguments<
            receiver = ScopedConstant<
              name = :HTTP,
              parent = ConstantAccess<name = :Net>
            >,
            name = :new
          >
        EOT
      end

      # Net::HTTP::Proxy('proxy.example.com', 8080)
      def pattern_net_http_proxy
        <<-EOT
          Send | SendWithArguments
          <
            receiver = ScopedConstant<
              parent = ConstantAccess<
                name = :Net
              >,
              name = :HTTP
            >,
            name = :Proxy
          >
        EOT
      end
    end
  end
end