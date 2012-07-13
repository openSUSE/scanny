require_relative "scanny/ruby_version_check"
require_relative "scanny/cli"
require_relative "scanny/issue"
require_relative "scanny/reporters"
require_relative "scanny/runner"
require_relative "scanny/checks/check"
require_relative "scanny/checks/helpers"

Dir[File.dirname(__FILE__) + "/scanny/checks/**/*_check.rb"].each do |file|
  require file
end
