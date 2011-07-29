class ScannyTask < Rake::TaskLib
  attr_accessor :name
  attr_accessor :patterns
  attr_accessor :verbose

  def initialize name = :scanny, patterns = nil
    @name      = name
    @patterns  = patterns || %w(app/**/*.rb lib/**/*.rb spec/**/*.rb test/**/*.rb)
    @verbose   = Rake.application.options.trace

    yield self if block_given?

    define
  end

  def define
    desc "Check for security issues in: #{patterns.join(', ')}"
    task name do
      runner = Scanny::Runner.new

      issues = []
      patterns.each do |pattern|
        Dir.glob(pattern).each { |file| issues += runner.check_file(file) }
      end

      issues.each {|issue| puts issue}

      raise "Found #{issues.size} issues." unless issues.empty?
    end
    self
  end
end
