require "spec_helper"

module Scanny::Checks
  describe HTTPUsageCheck do
    before do
      @runner = Scanny::Runner.new(HTTPUsageCheck.new)
      @message =  "Connecting to the server without encryption " +
                  "can facilitate sniffing traffic"
      @issue = issue(:low, @message, 319)
    end

    it "reports \"http://\" correctly" do
      @runner.should check("'http://'").with_issue(@issue)
    end

    it "reports \"@http.connect('http://server.com')\" correctly" do
      @runner.should check("@http.connect('http://server.com')").with_issue(@issue)
    end
  end
end
