# ipu_util_plot tool
This tool is used to plot the ipu utilization of smlu instances for specific
card, which is benefit for visualizing the ipu utilization change curve under
the control of 'cambricon-util_drv.ko' module, and help us adjust the control
parameters in 'cambricon-util_drv.ko' module.

It can plot both usage and quota data for all smlu instances of the specific
card in one picture, which is current and the restricted max ipu util separately.

# dependence
This tool depends on gnuplot, thus need install it first as follows:

Ubuntu: sudo apt-get install gnuplot
Centos: sudo yum install gnuplot

# usage
To use it, go with the following steps:
1. generate corresponding trace.json file during smlu instance in running,
   refer to "Cambricon-sMLU-User-Guide" for this;
2. compile the plot tool with 'make' command;
3. run 'ipu_util_plot' with correct args, use '--help' to check usage info;
4. finally, '.svg' file will be generated to your setting path,
   open it with explorer.
