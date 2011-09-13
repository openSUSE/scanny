# 2011/09/12: common/lib/command.rb
# Copyright © 2011 Novell, Inc.  All Rights Reserved.
#
# THIS WORK IS SUBJECT TO U.S. AND INTERNATIONAL COPYRIGHT LAWS AND TREATIES.
# IT MAY NOT BE USED, COPIED, DISTRIBUTED, DISCLOSED, ADAPTED, PERFORMED,
# DISPLAYED, COLLECTED, COMPILED, OR LINKED WITHOUT NOVELL'S PRIOR WRITTEN
# CONSENT.  USE OR EXPLOITATION OF THIS WORK WITHOUT AUTHORIZATION COULD SUBJECT
# THE PERPETRATOR TO CRIMINAL AND CIVIL LIABILITY.
#
# NOVELL PROVIDES THE WORK "AS IS," WITHOUT ANY EXPRESS OR IMPLIED WARRANTY,
# INCLUDING WITHOUT THE IMPLIED WARRANTIES OF MERCHANTABILITY, FITNESS FOR A
# PARTICULAR PURPOSE, AND NON-INFRINGEMENT. NOVELL, THE AUTHORS OF THE WORK, AND
# THE OWNERS OF COPYRIGHT IN THE WORK ARE NOT LIABLE FOR ANY CLAIM, DAMAGES, OR
# OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT, OR OTHERWISE, ARISING
# FROM, OUT OF, OR IN CONNECTION WITH THE WORK OR THE USE OR OTHER DEALINGS IN THE
# WORK.

# Contains methods for executing external commands safely and conveniently.
module Command
  # Exception raised when a command execution fails.
  class ExecutionFailed < StandardError
    attr_reader :command, :args, :status

    def initialize(command, args, status, message = nil)
      super(message)
      @command = command
      @args    = args
      @status  = status
    end
  end

  def self.run(command, *args)
    options = args.last.is_a?(Hash) ? args.pop : {}

    capture = options[:capture]
    stdin   = options[:stdin] || ""
    logger  = options[:logger]

    if command.is_a?(Array)
      args    = command[1..-1]
      command = command.first
    end

    pass_stdin = !stdin.empty?
    pipe_stdin_read, pipe_stdin_write = pass_stdin ? IO.pipe : [nil, nil]

    capture_stdout = [:stdout, [:stdout, :stderr]].include?(capture) || logger
    pipe_stdout_read, pipe_stdout_write = capture_stdout ? IO.pipe : [nil, nil]

    capture_stderr = [:stderr, [:stdout, :stderr]].include?(capture) || logger
    pipe_stderr_read, pipe_stderr_write = capture_stderr ? IO.pipe : [nil, nil]

    if logger
      args_description = if args.empty?
        "no arguments"
      else
        "arguments #{args.map(&:inspect).join(", ")}"
      end
      logger.debug "Executing command #{command.inspect} with #{args_description}."
      logger.debug "Standard input: " + (stdin.empty? ? "(none)" : stdin)
    end

    pid = fork do
      begin
        if pass_stdin
          pipe_stdin_write.close
          STDIN.reopen(pipe_stdin_read)
          pipe_stdin_read.close
        else
          STDIN.reopen("/dev/null", "r")
        end

        if capture_stdout
          pipe_stdout_read.close
          STDOUT.reopen(pipe_stdout_write)
          pipe_stdout_write.close
        else
          STDOUT.reopen("/dev/null", "w")
        end

        if capture_stderr
          pipe_stderr_read.close
          STDERR.reopen(pipe_stderr_write)
          pipe_stderr_write.close
        else
          STDERR.reopen("/dev/null", "w")
        end

        # All file descriptors from 3 above should be closed here, but since I
        # don't know about any way how to detect the maximum file descriptor
        # number portably in Ruby, I didn't implement it. Patches welcome.

        exec([command, command], *args) # TESTCASE: CWE-78, CWE-88
      rescue SystemCallError => e
        exit!(127)
      end
    end

  end
end
