class ScannyTask < Rake::TaskLib
  attr_accessor :name
  attr_accessor :patterns
  attr_accessor :config
  attr_accessor :verbose

  def initialize name = :scanny, patterns = nil, config = nil
    @name      = name
    @patterns  = patterns || %w(app/**/*.rb lib/**/*.rb spec/**/*.rb test/**/*.rb)
    @config    = config
    @verbose   = Rake.application.options.trace

    yield self if block_given?

    define
  end

  def define
    desc "Check for security issues in: #{patterns.join(', ')}"
    task name do
      runner = Scanny::Runner.new

      runner.config = config if config

      patterns.each do |pattern|
        Dir.glob(pattern).each { |file| runner.check_file(file) }
      end

      runner.issues.each {|issue| puts issue}

      raise "Found #{runner.issues.size} issues." unless runner.issues.empty?
    end
    self
  end
end
