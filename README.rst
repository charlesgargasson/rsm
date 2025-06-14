
###
RSM
###

| ReverseShell Manager for goBack https://gitlab.com/charles.gargasson/goback
| But works with any classic reverseshell payload

*******
Install
*******

| Install it system wide in order to use it with sudo when you need to listen on '0-1000' ports range

.. code-block:: bash

    sudo pipx install git+https://github.com/charlesgargasson/rsm.git@main --global
    # sudo pipx uninstall rsm
    # sudo pipx upgrade rsm

|

*****
Usage
*****

.. code-block:: bash

    # Start server for incomming reverseshell connections
    sudo rsmserver -l 0.0.0.0:53 -l 0.0.0.0:1337

    # Start cli to interract with etablished shells
    rsm

|

*****
Debug
*****

.. code-block:: bash

    # Checking if line is buffered or not
    for i in {1..10};do echo -n $i;sleep 1;done