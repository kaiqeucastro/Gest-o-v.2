# Controle financeiro

## Iniciar

Requer Python 3.10 ou superior; não há dependências externas.

```powershell
python server.py
```

Abra http://127.0.0.1:8000. O SQLite cria `financeiro.db` automaticamente na primeira execução. Crie um usuário pela opção **Criar conta**; os lançamentos e contas ficam associados a esse usuário.

Para exigir um código de convite ao criar contas, defina-o antes de iniciar o servidor:

```powershell
$env:FINANCE_INVITE_CODE = "KIQ"
python server.py
```

O banco é local a esta máquina e não sincroniza com outros dispositivos. Faça cópia de segurança de `financeiro.db`. O servidor, por padrão, aceita conexões apenas do próprio computador; não o exponha diretamente à internet.
