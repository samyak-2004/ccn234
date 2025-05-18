import pkg_resources

def export_requirements(filename="requirements.txt"):
    packages = pkg_resources.working_set
    with open(filename, "w") as f:
        for package in packages:
            f.write(f"{package.key}=={package.version}\n")
    print(f"✅ Requirements exported to {filename}")

if __name__ == "__main__":
    export_requirements()
