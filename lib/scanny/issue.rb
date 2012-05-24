module Scanny
  class Issue
    attr_reader :file, :line, :impact, :message, :cwe

    def initialize(file, line, impact, message, cwe = nil)
      @file, @line, @impact, @message, @cwe = file, line, impact, message, cwe
    end

    def ==(other)
      other.instance_of?(self.class) &&
        @file == other.file &&
        @line == other.line &&
        @impact == other.impact &&
        @message == other.message &&
        @cwe == other.cwe
    end

    def to_s
      cwe_suffix = if @cwe
        " (" + Array(@cwe).map { |cwe| "CWE-#{cwe}" }.join(", ") + ")"
      else
        ""
      end

      "[#{@impact}] #{@file}:#{@line}: #{@message}#{cwe_suffix}"
    end
  end
end
