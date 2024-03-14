
How to Use
----------
- Firstly, Get the MLU driver compiled package, naming "cambricon-mlu-driver-release/debug-$VERSION-$DATA-$COMMOIT.tar.gz" for example

- make the installation package
 -- $1 is install package type, support 'release/debug'
 -- $2 is interrupt type, support 'msi/msix/intx'
 -- $3 is package making method, auto or manual, it is considered as auto if blank"
          if not auto/manual or blank, must input the built package's absolute path"
 Usage example:
 ./mlu_package.sh release msi
 ./mlu_package.sh debug msi manual
 ./mlu_package.sh release msi /home/svc-jenkins/workspace/mlu_built_pkg

Contents of the cambricon built package is as follows:
built_package_release
├──
│   └── firmwares
├──
│   ├── cndrv_host
│   └ cnmon
└── VERSION

5 directories, 1 file
