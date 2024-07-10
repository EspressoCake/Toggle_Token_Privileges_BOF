# Toggle_Token_Privileges_BOF

##
#### What is this?
- An (almost) syscall-only BOF file intended to either add or remove token privileges within the context of your current process.
##
#### Who wrote it?
- Justin Lucas  (@the_bit_diddler)
- Brad Campbell (@hackersoup)
##
#### What problem are you trying to solve?
- There are many boilerplate options to enable a specific subset of privileges; traditionally, this has been almost entirely centered around `SE_DEBUG`
    - Why not let *you*, the operator have the power of choice? Pick to add-or-remove from an à la carte help menu.
    ![](https://i.ibb.co/D9zLFdt/help-text.png)
##
#### How do I build this?
```sh
git clone https://github.com/EspressoCake/Toggle_Token_Privileges_BOF.git
cd Toggle_Token_Privileges_BOF/src
make
```

#### How do I use this?
- Load the `Aggressor` `.cna` file from the `dist` directory, after building
- Determine whatever relative privilege number (see the help menu) you wish to apply to your current process token
- From a given `Beacon`:
    ```sh
    # Getting general help
    syscall_enable_priv
    
    # Adding a privilege (SE_DEBUG)
    syscall_enable_priv 20
    
    # Removing a privilege (SE_DEBUG)
    syscall_disable_priv 20
    ```

##### For Havoc (https://havocframework.com/)
- Load the `.py` from the `Script Manager`
- Determine whatever relative privilege number (see the help menu) you wish to apply to your current process token
- From a given `Beacon`:
    ```sh
    # Getting general help
    help toggle_privs_bof
    
    # Getting the list of privilege IDs
    toggle_privs_bof
    
    # Adding a privilege (SE_DEBUG)
    toggle_privs_bof enable 20
    
    # Removing a privilege (SE_DEBUG)
    toggle_privs_bof disable 20
    ```

##
#### I tend to touch the stove carelessly, how are you taking care of the injury-prone?
- Currently, the `Aggressor` script has safeguards
    - The current `Beacon` is checked to ensure that it is administrative, and an `x64` process
    ![](https://i.ibb.co/598XQSG/guardrails.png)
##
#### What does the output look like?
##### Adding/Revoking Current Process Token Privileges
![](https://i.ibb.co/8bZYQW7/rev-priv.png)


