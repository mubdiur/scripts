sudo dnf install -y epel-release && \
sudo dnf install -y git vim nano htop fastfetch zsh util-linux-user \
  tmux fzf ripgrep bat fd-find tree wget curl jq unzip tar ncdu && \
curl -sSfL https://raw.githubusercontent.com/ajeetdsouza/zoxide/main/install.sh | sh && \
sudo chsh -s $(which zsh) $USER && \
RUNZSH=no CHSH=no sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)" && \
git clone --depth=1 https://github.com/romkatv/powerlevel10k.git ~/.oh-my-zsh/custom/themes/powerlevel10k && \
git clone https://github.com/zsh-users/zsh-autosuggestions ~/.oh-my-zsh/custom/plugins/zsh-autosuggestions && \
git clone https://github.com/zsh-users/zsh-syntax-highlighting ~/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting && \
sed -i '1s|^|export PATH="$HOME/.local/bin:$PATH"\n|' ~/.zshrc && \
sed -i 's/ZSH_THEME="robbyrussell"/ZSH_THEME="powerlevel10k\/powerlevel10k"/' ~/.zshrc && \
sed -i 's/plugins=(git)/plugins=(git zoxide zsh-autosuggestions zsh-syntax-highlighting fzf z)/' ~/.zshrc