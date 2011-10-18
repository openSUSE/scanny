require "spec_helper"

module Scanny::Checks
  describe FDLeakCheck do
    before :each do
      @runner = Scanny::Runner.new(FDLeakCheck.new)
      @issue = issue(:info, "Using File.open without block might lead to file descriptor leak, unless file is explicitly closed.")
    end

    it "reports \"File.open\" without block correctly" do
      @runner.should check('File.open("foo", "r").read').with_issue(@issue)
      @runner.should check('File.open("foo", "w") { |f| f.write "hi" }').without_issues
      @runner.should check('File.open("foo", "w") do |f| f.write "hi" end').without_issues
    end
  end
end
