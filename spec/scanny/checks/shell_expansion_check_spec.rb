require File.expand_path(File.dirname(__FILE__) + '/../../spec_helper')

describe Scanny::Checks::ShellExpansionCheck do
  before(:each) do
    @scanny = Scanny::Core::Runner.new(Scanny::Checks::ShellExpansionCheck.new)
  end

  it "does not report regular method calls" do
    content = <<-EOT
      foo
    EOT

    @scanny.check_content(content)
    issues = @scanny.issues

    issues.should be_empty
  end

  it "reports \"exec\" calls" do
    content = <<-EOT
      exec
    EOT

    @scanny.check_content(content)
    issues = @scanny.issues

    issues.size.should == 1
    issues[0].to_s.should == "[high] dummy-file.rb:2 - The \"exec\" method can pass the executed command through shell exapnsion."
  end

  it "reports \"system\" calls" do
    content = <<-EOT
      system
    EOT

    @scanny.check_content(content)
    issues = @scanny.issues

    issues.size.should == 1
    issues[0].to_s.should == "[high] dummy-file.rb:2 - The \"system\" method can pass the executed command through shell exapnsion."
  end
end

