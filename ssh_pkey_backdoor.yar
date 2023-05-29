rule ssh_public_key_infected
{
    meta:
        description = "SSH Public Key is infected to backdoor or ... ."
		ref = "https://blog.thc.org/infecting-ssh-public-keys-with-backdoors"
        author = "seyyid"
		site = "onhexgroup.ir"

    strings:
        $backdoor = "command="

    condition:
        $backdoor
}