import subprocess
import whatweb

class RunCommand:
    def __init__(self):
        self.__command = whatweb.whatweb('http://17.0.0.0').getCommand()

    def command_to_run(self):
        print(self.__command)

# Create an instance of the class
run_command_instance = RunCommand()
# Call the method on the instance
run_command_instance.command_to_run()
