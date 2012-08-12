require "spec_helper"

module Scanny::Checks
  describe TempFileOpenCheck do
    before do
      @runner = Scanny::Runner.new(TempFileOpenCheck.new)
      @message =  "Access to the temporary files can lead to" +
                  "unauthorized access to data"
      @issue = issue(:medium, @message, 377)
    end

    it "reports \"File.open('/home/app/tmp/file')\" correctly" do
      @runner.should  check("File.open('/home/app/tmp/file')").
                      with_issues([@issue, @issue])
    end

    it "reports \"mkdir_p('/rails/tmp/my/dir')\" correctly" do
      @runner.should  check("mkdir_p('/rails/tmp/my/dir')").
                      with_issues([@issue, @issue])
    end
  end
end
