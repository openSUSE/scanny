module Scanny
  module Tools
    def build_paths
      paths = ARGV.map do |path|
        path += "/**/*.rb" if File.directory?(path)
        path
      end
      paths << "./**/*.rb" if paths.size == 0

      paths
    end

    def require_checks(checks)
      checks = checks.to_s.split(",").map(&:strip)

      checks.each do |directory|
        Dir[directory + "/**/*.rb"].each do |file|
          require file
        end
      end
    end

    def disable_checks(checks)
      checks = checks.to_s.split(",").map(&:strip)

      checks.each do |check|
        checks = check.split('::')
        checks.shift if checks.empty? || checks.first.empty?
        delete = checks.slice!(-1)

        constant = Scanny::Checks
        checks.each do |name|
          constant = constant.const_defined?(name) ? constant.const_get(name) : constant.const_missing(name)
        end

        constant.instance_eval do
          remove_const(delete)
        end
      end
    end

    def show_version
      puts Scanny::VERSION
      exit 0
    end
  end
end