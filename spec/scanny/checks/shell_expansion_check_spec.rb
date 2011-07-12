require File.expand_path(File.dirname(__FILE__) + '/../../spec_helper')

describe Scanny::Checks::ShellExpansionCheck do

  before(:each) do
    @scanny = Scanny::Core::Runner.new(Scanny::Checks::ShellExpansionCheck.new)
  end

  it "does not report regular method calls" do
    @scanny.should parse("foo").without_issues
  end

  it "reports \"exec\" calls" do
    @scanny.should parse("exec").with_issue(:high,
      "The \"exec\" method can pass the executed command through shell exapnsion.")
  end

  it "reports \"system\" calls" do
    @scanny.should parse("system").with_issue(:high,
      "The \"system\" method can pass the executed command through shell exapnsion.")
  end
end

