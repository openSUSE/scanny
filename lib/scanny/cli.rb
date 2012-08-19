module Scanny
  module CLI
    def build_paths
      paths = ARGV.map do |path|
        path += "/**/*.rb" if File.directory?(path)
        path
      end
      paths << "./app/**/*.rb" if paths.size == 0

      paths.map { |path| path.gsub('//', '/') }
    end

    def require_checks(checks)
      checks = checks.to_s.split(",").map(&:strip)

      checks.each do |directory|
        Dir[directory + "/**/*.rb"].each do |file|
          require File.expand_path(file, Dir.pwd)
        end
      end
    end

    def runner_with_custom_checks(runner, disabled_checks, strict = false)
      disabled_checks = disabled_checks.to_s.split(",").map(&:strip)

      runner.checks.reject! do |check|
        disabled_checks.any? { |ch| check.class.name == ch } ||
        (check.strict? && !strict)
      end

      runner
    end

    def use_parser(version)
      return unless version
      case version
        when '18'
          Rubinius::Melbourne
        when '19'
          Rubinius::Melbourne19
        else
          $stderr.puts "I can not recognize the version of the parser: #{version}"
          exit 2
      end
    end
  end
end
