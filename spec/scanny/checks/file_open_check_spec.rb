require "spec_helper"

module Scanny::Checks
  describe FileOpenCheck do
    before do
      @runner = Scanny::Runner.new(FileOpenCheck.new)
      @message =  "Operations on files in code can lead to" +
                  "unauthorized access to data"
      @issue = issue(:info, @message, 0)
    end

    it "reports \"File.open('/home/app/tmp/file')\" correctly" do
      @runner.should  check("File.open('/home/app/tmp/file')").
                      with_issue(@issue)
    end

    it "reports \"FileUtils.chmod(0755, '/usr/bin/ruby')\" correctly" do
      @runner.should  check("FileUtils.chmod(0755, '/usr/bin/ruby')").
                      with_issue(@issue)
    end
  end
end
