require File.expand_path(File.dirname(__FILE__) + "/scanny/issue")
require File.expand_path(File.dirname(__FILE__) + "/scanny/runner")
require File.expand_path(File.dirname(__FILE__) + "/scanny/checks/check")

Dir[File.expand_path(File.dirname(__FILE__) + "/scanny/checks/*_check.rb")].each do |file|
  require file
end
