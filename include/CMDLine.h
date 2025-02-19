#ifndef CMDLINE_H
#define CMDLINE_H
#include <string>
#include <vector>
#include <cstdlib> // for std::atoi
#include <iostream>

// Show help information
void show_help(const std::string &command = "")
{
    if (command.empty())
    {
        std::cout << "Usage:\n";
        std::cout << "  cicflowmeter [commands and flags] ...\n\n";
        std::cout << "Available Commands:\n";
        std::cout << "  tcp       Set TCP timeout (default is 600 seconds)\n";
        std::cout << "  udp       Set UDP timeout (default is 600 seconds)\n";
        std::cout << "  help      Show help information\n\n";
        std::cout << "Flags:\n";
        std::cout << "  -h, --help      Show help for a command\n";
        std::cout << "  -t, --timeout   Set timeout value (in seconds)\n\n";
        std::cout << "You can chain commands in one call, e.g.\n";
        std::cout << "  cicflowmeter tcp -t 30 udp -t 60\n";
        std::cout << "Use \"cicflowmeter [command] --help\" for more information about a command.\n";
    }
    else if (command == "tcp")
    {
        std::cout << "Set TCP timeout (default is 600 seconds)\n\n";
        std::cout << "Usage:\n";
        std::cout << "  cicflowmeter tcp -t <timeout_value>\n\n";
        std::cout << "Flags:\n";
        std::cout << "  -t, --timeout   Set TCP timeout value (in seconds)\n";
    }
    else if (command == "udp")
    {
        std::cout << "Set UDP timeout (default is 600 seconds)\n\n";
        std::cout << "Usage:\n";
        std::cout << "  cicflowmeter udp -t <timeout_value>\n\n";
        std::cout << "Flags:\n";
        std::cout << "  -t, --timeout   Set UDP timeout value (in seconds)\n";
    }
    else
    {
        std::cerr << "Unknown command: " << command << "\n";
    }
}

// A small struct to hold a command and its parsed timeout
struct CommandInfo
{
    std::string command;
    int timeout_value = 600; // Default timeout value is 600 seconds
};

int parse_arguments(int argc, char *argv[], int *tcp_timeout, int *udp_timeout)
{
    if (argc < 2)
    {
        // No commands provided; show global help
        show_help();
        return 1;
    }

    std::vector<CommandInfo> commands;

    for (int i = 1; i < argc;)
    {
        std::string arg = argv[i];

        if (arg == "help")
        {
            if (i + 1 < argc && (std::string(argv[i + 1]) == "tcp" ||
                                 std::string(argv[i + 1]) == "udp"))
            {
                show_help(argv[i + 1]);
                return 0;
            }
            else
            {
                show_help();
                return 0;
            }
        }
        else if (arg == "tcp" || arg == "udp")
        {
            CommandInfo info;
            info.command = arg;
            i++;

            while (i < argc)
            {
                std::string next_arg = argv[i];
                if (next_arg == "tcp" || next_arg == "udp" || next_arg == "help")
                {
                    break;
                }
                if (next_arg == "-t" || next_arg == "--timeout")
                {
                    if (i + 1 < argc)
                    {
                        info.timeout_value = std::atoi(argv[i + 1]);
                        i += 2;
                    }
                    else
                    {
                        std::cerr << "Error: Missing value after " << next_arg << "\n";
                        show_help(info.command);
                        return 1;
                    }
                }
                else if (next_arg == "-h" || next_arg == "--help")
                {
                    show_help(info.command);
                    return 0;
                }
                else
                {
                    std::cerr << "Unknown flag or missing argument: " << next_arg << "\n";
                    show_help(info.command);
                    return 1;
                }
            }
            commands.push_back(info);
        }
        else
        {
            std::cerr << "Unknown command or argument: " << arg << "\n";
            show_help();
            return 1;
        }
    }

    for (auto &cmdInfo : commands)
    {
        if (cmdInfo.command == "tcp")
        {
            std::cout << "TCP timeout set to: " << cmdInfo.timeout_value << " seconds\n";
            *tcp_timeout = cmdInfo.timeout_value;
        }
        else if (cmdInfo.command == "udp")
        {
            std::cout << "UDP timeout set to: " << cmdInfo.timeout_value << " seconds\n";
            *udp_timeout = cmdInfo.timeout_value;
        }
    }

    return 0;
}

#endif