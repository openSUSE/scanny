module Scanny
  module CLI
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

    def runner_with_custom_checks(disabled_checks, strict = false)
      disabled_checks = disabled_checks.to_s.split(",").map(&:strip)

      runner = Scanny::Runner.new
      runner.checks.reject! do |check|
        disabled_checks.any? { |ch| check.class.name == ch } ||
        (check.strict? && !strict)
      end

      runner
    end
  end
end