CARGOPACKAGE=$(cat start-os/core/Cargo.lock | grep "name =" | cut --delimiter="\"" --fields=2)

for package in ${CARGOPACKAGE[@]}; do
    echo "package name: $package"
    guix import --insert=start9-cli.scm crate -f start-os/core/Cargo.lock $package
done