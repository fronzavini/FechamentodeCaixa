# =====================================================================
# SEÇÃO 1: IMPORTAÇÕES ESSENCIAIS
# Todas as bibliotecas necessárias para o projeto são importadas aqui.
# =====================================================================
from flask import Flask, render_template, request, redirect, url_for, session, flash, Blueprint
from functools import wraps
from werkzeug.security import generate_password_hash, check_password_hash
import mysql.connector

# =====================================================================
# SEÇÃO 2: CONFIGURAÇÃO INICIAL DO APLICATIVO
# Configurações essenciais para a aplicação Flask e a conexão com o banco de dados.
# =====================================================================

# Cria a instância principal da aplicação Flask.
app = Flask(__name__)

# Define uma chave secreta para a aplicação, usada para proteger as sessões dos usuários.
# Em um ambiente de produção, esta chave deve ser mais complexa e mantida em segredo.
app.secret_key = 'chave-secreta-muito-segura-para-seu-projeto'

# Dicionário com as credenciais de acesso ao banco de dados MySQL.
db_config = {
    'host': 'localhost',
    'user': 'root',
    'password': '',
    'database': 'caixa'  # Nome do banco de dados utilizado.
}


def table_has_column(table_name, column_name):
    """Verifica se uma tabela possui determinada coluna no banco configurado.
    Retorna True/False. Usa information_schema para checagem em tempo de execução.
    """
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute(
            "SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = %s AND table_name = %s AND column_name = %s",
            (db_config['database'], table_name, column_name)
        )
        exists = cursor.fetchone()[0] > 0
    except Exception:
        exists = False
    finally:
        try:
            cursor.close()
            conn.close()
        except Exception:
            pass
    return exists

# =====================================================================
# SEÇÃO 3: DECORADOR DE AUTENTICAÇÃO DE ADMIN
# Garante que apenas usuários administradores logados possam acessar certas rotas.
# =====================================================================
def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # 1. Verifica se 'usuario_id' não está na sessão, o que indica que o usuário não está logado.
        if 'usuario_id' not in session:
            flash("Você precisa fazer login para acessar esta página.", "erro")
            return redirect(url_for('login'))
        
        # 2. Verifica se o tipo de usuário na sessão não é '1' (que representa o administrador).
        if session.get('tipo_usuario') != 1:
            flash("Acesso negado. Você não tem permissão para acessar esta página.", "erro")
            # Redireciona para a página inicial se o usuário não for administrador.
            return redirect(url_for('home'))
        
        # 3. Se todas as verificações passarem, a função original (a rota) é executada.
        return f(*args, **kwargs)
    return decorated_function

# =====================================================================
# SEÇÃO 4: ROTAS PRINCIPAIS E DE AUTENTICAÇÃO
# Controlam o acesso, login, cadastro e logout dos usuários.
# =====================================================================

@app.route('/')
def home():
    """ Rota principal. Redireciona o usuário com base no seu status de login. """
    if 'usuario_id' in session:
        # Se for administrador, vai para o dashboard.
        if session.get('tipo_usuario') == 1:
            return redirect(url_for('admin.dashboard'))
        # Se for um usuário comum, é deslogado, pois não tem acesso ao painel.
        flash("Sua conta não tem permissão de acesso ao painel.", "info")
        return redirect(url_for('logout'))
    # Se não estiver logado, vai para a página de login.
    return redirect(url_for('login'))


@app.route('/cadastro', methods=['GET', 'POST'])
def cadastro():
    """ Rota para a página de cadastro de novos usuários. """
    # Se o formulário for enviado (método POST).
    if request.method == 'POST':
        # Coleta os dados do formulário.
        nome = request.form['nome']
        username = request.form['username']
        email = request.form['email']
        # Gera um hash seguro para a senha antes de salvar no banco.
        senha = generate_password_hash(request.form['senha'])
        
        # Conecta ao banco de dados.
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(buffered=True)
        
        # Verifica se o nome de usuário ou e-mail já existem para evitar duplicatas.
        cursor.execute("SELECT * FROM usuario WHERE username_usuario = %s OR email_usuario = %s", (username, email))
        if cursor.fetchone():
            flash("Nome de usuário ou e-mail já cadastrado.", "erro")
            cursor.close()
            conn.close()
            return redirect(url_for('cadastro'))
        
        # Insere o novo usuário no banco. Por padrão, tipo_usuario=2 (usuário comum) e conta_ativa=True.
        cursor.execute("""INSERT INTO usuario (nome_usuario, username_usuario, password_usuario, email_usuario, tipo_usuario, conta_ativa)
                          VALUES (%s, %s, %s, %s, %s, %s)""", (nome, username, senha, email, 1, True))
        conn.commit()  # Confirma a transação.
        cursor.close()
        conn.close()
        
        flash("Cadastro realizado com sucesso! Você já pode fazer login.", "sucesso")
        return redirect(url_for('login'))
        
    # Se for uma requisição GET, apenas renderiza a página de cadastro.
    return render_template('cadastro.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    """ Rota para a página de login do sistema. """
    if request.method == 'POST':
        username = request.form['username'].strip()
        senha = request.form['senha'].strip()
        
        conn = mysql.connector.connect(**db_config)
        # `dictionary=True` faz o cursor retornar os resultados como dicionários (útil para acessar colunas pelo nome).
        cursor = conn.cursor(dictionary=True, buffered=True)
        
        # Busca o usuário pelo nome de usuário fornecido.
        cursor.execute("SELECT * FROM usuario WHERE username_usuario = %s", (username,))
        usuario = cursor.fetchone()
        
        cursor.close()
        conn.close()
        
        # Verifica se o usuário existe e se a senha fornecida corresponde ao hash salvo no banco.
        if usuario and check_password_hash(usuario['password_usuario'], senha):
            # Verifica se a conta não está desativada.
            if not usuario['conta_ativa']:
                flash("Esta conta está desativada. Entre em contato com o administrador.", "erro")
                return redirect(url_for('login'))
            
            # Salva os dados do usuário na sessão para mantê-lo logado.
            session['usuario_id'] = usuario['cod_usuario']
            session['usuario_nome'] = usuario['nome_usuario']
            session['tipo_usuario'] = usuario['tipo_usuario']
            
            # Redireciona para o dashboard se for administrador.
            if usuario['tipo_usuario'] == 1:
                return redirect(url_for('admin.dashboard'))
            else:
                # Se não for admin, exibe um erro e volta para o login.
                flash("Acesso permitido apenas para administradores.", "erro")
                return redirect(url_for('login'))
        else:
            # Se o usuário não existir ou a senha estiver incorreta.
            flash("Usuário ou senha inválidos.", "erro")
            return redirect(url_for('login'))
            
    return render_template('login.html')


@app.route('/logout')
def logout():
    """ Rota para remover os dados do usuário da sessão (logout). """
    session.pop('usuario_id', None)
    session.pop('usuario_nome', None)
    session.pop('tipo_usuario', None)
    flash("Você saiu da sua conta.", "sucesso")
    return redirect(url_for('login'))


# =====================================================================
# SEÇÃO 5: ÁREA ADMINISTRATIVA (/sistema/admin/)
# Um Blueprint organiza um grupo de rotas relacionadas em um módulo.
# =====================================================================
admin_bp = Blueprint('admin', __name__, url_prefix='/sistema/admin')

@admin_bp.route('/')
@admin_required
def index():
    """ Rota raiz do admin, que apenas redireciona para o dashboard. """
    return redirect(url_for('admin.dashboard'))


@admin_bp.route('/dashboard')
@admin_required
def dashboard():
    """ Rota do painel de controle (dashboard) com estatísticas do sistema. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    
    # Coleta de dados para os cards de resumo.
    cursor.execute("SELECT COUNT(*) as total FROM produto")
    total_produtos = cursor.fetchone()['total']
    cursor.execute("SELECT COUNT(*) as total FROM categoria_produto")
    total_categorias = cursor.fetchone()['total']
    cursor.execute("SELECT COUNT(*) as total FROM venda")
    total_vendas = cursor.fetchone()['total']
    
    # Cálculo do saldo atual do caixa (entradas - saídas).
    cursor.execute("""
        SELECT 
            COALESCE((SELECT SUM(valor) FROM caixa WHERE tipo = 'entrada'), 0) - 
            COALESCE((SELECT SUM(valor) FROM caixa WHERE tipo = 'saida'), 0) 
        AS saldo
    """)
    saldo_caixa = cursor.fetchone()['saldo']

    # Busca as últimas 5 vendas para exibir na tabela de vendas recentes.
    cursor.execute("""
        SELECT v.cod_venda, v.total, v.data_venda, u.nome_usuario 
        FROM venda v JOIN usuario u ON v.cod_usuario = u.cod_usuario 
        ORDER BY v.data_venda DESC LIMIT 5
    """)
    vendas_recentes = cursor.fetchall()
    
    cursor.close()
    conn.close()

    # Renderiza a página do dashboard, passando todos os dados coletados para o template.
    return render_template('dashboard.html', 
                           total_produtos=total_produtos,
                           total_categorias=total_categorias,
                           total_vendas=total_vendas,
                           saldo_caixa=saldo_caixa,
                           vendas_recentes=vendas_recentes)

# --- CRUD para Usuários ---
@admin_bp.route('/usuarios')
@admin_required
def usuarios():
    """ Rota para listar todos os usuários do sistema. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT cod_usuario, nome_usuario, username_usuario, email_usuario, tipo_usuario, conta_ativa FROM usuario ORDER BY nome_usuario ASC")
    lista_usuarios = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('usuarios.html', usuarios=lista_usuarios)

@admin_bp.route('/usuarios/editar/<int:cod>', methods=['GET', 'POST'])
@admin_required
def editar_usuario(cod):
    """ Rota para editar o tipo e o status de um usuário. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        tipo_usuario = request.form['tipo_usuario']
        # Verifica se o checkbox 'conta_ativa' foi marcado no formulário.
        conta_ativa = 'conta_ativa' in request.form

        cursor.execute("UPDATE usuario SET tipo_usuario = %s, conta_ativa = %s WHERE cod_usuario = %s", (tipo_usuario, conta_ativa, cod))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Usuário atualizado com sucesso!", "sucesso")
        return redirect(url_for('admin.usuarios'))

    # Se GET, busca os dados do usuário para preencher o formulário de edição.
    cursor.execute("SELECT cod_usuario, nome_usuario, username_usuario, email_usuario, tipo_usuario, conta_ativa FROM usuario WHERE cod_usuario = %s", (cod,))
    usuario = cursor.fetchone()
    cursor.close()
    conn.close()
    if not usuario:
        flash("Usuário não encontrado.", "erro")
        return redirect(url_for('admin.usuarios'))
        
    return render_template('editar_usuario.html', usuario=usuario)

# --- CRUD para PVP ---
@admin_bp.route('/pvps')
@admin_required
def pvps():
    """ Rota para listar todos os PVPs. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT * FROM pvp ORDER BY nome_pvp ASC")
    lista_pvps = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('pvps.html', pvps=lista_pvps)

@admin_bp.route('/pvps/cadastrar', methods=['GET', 'POST'])
@admin_required
def cadastrar_pvp():
    """ Rota para cadastrar um novo PVP. """
    if request.method == 'POST':
        nome = request.form['nome_pvp']
        percentual = request.form['percentual']
        tipo = request.form['tipo_pvp']
        
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor(dictionary=True)

        # Validação para impedir o cadastro de mais de um PVP Global ativo.
        if tipo == 'global':
            cursor.execute("SELECT cod_pvp FROM pvp WHERE tipo_pvp = 'global' AND ativo = TRUE")
            if cursor.fetchone():
                flash("Já existe um PVP Global ativo. Inative o PVP existente antes de cadastrar um novo.", "erro")
                cursor.close()
                conn.close()
                return redirect(url_for('admin.cadastrar_pvp'))

        query = "INSERT INTO pvp (nome_pvp, percentual, tipo_pvp) VALUES (%s, %s, %s)"
        cursor.execute(query, (nome, percentual, tipo))
        conn.commit()
        cursor.close()
        conn.close()
        flash("PVP cadastrado com sucesso!", "sucesso")
        return redirect(url_for('admin.pvps'))

    return render_template('cadastrar_pvp.html')

@admin_bp.route('/pvps/editar/<int:cod>', methods=['GET', 'POST'])
@admin_required
def editar_pvp(cod):
    """ Rota para editar um PVP existente. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    if request.method == 'POST':
        nome = request.form['nome_pvp']
        percentual = request.form['percentual']
        tipo = request.form['tipo_pvp']
        ativo = 'ativo' in request.form
        
        # Validação para impedir que mais de um PVP Global seja ativado.
        if tipo == 'global' and ativo:
            # Procura por outro PVP global ativo que não seja o que está sendo editado.
            cursor.execute("SELECT cod_pvp FROM pvp WHERE tipo_pvp = 'global' AND ativo = TRUE AND cod_pvp != %s", (cod,))
            if cursor.fetchone():
                flash("Já existe outro PVP Global ativo. Inative o PVP existente antes de ativar este.", "erro")
                cursor.close()
                conn.close()
                return redirect(url_for('admin.editar_pvp', cod=cod))

        query = """
            UPDATE pvp SET nome_pvp = %s, percentual = %s, tipo_pvp = %s, ativo = %s
            WHERE cod_pvp = %s
        """
        cursor.execute(query, (nome, percentual, tipo, ativo, cod))
        conn.commit()
        cursor.close()
        conn.close()
        flash("PVP atualizado com sucesso!", "sucesso")
        return redirect(url_for('admin.pvps'))

    # Se GET, busca dados do PVP para preencher o formulário.
    cursor.execute("SELECT * FROM pvp WHERE cod_pvp = %s", (cod,))
    pvp = cursor.fetchone()
    if not pvp:
        flash("PVP não encontrado.", "erro")
        return redirect(url_for('admin.pvps'))
    
    cursor.close()
    conn.close()
    return render_template('editar_pvp.html', pvp=pvp)

@admin_bp.route('/pvps/excluir/<int:cod>', methods=['POST'])
@admin_required
def excluir_pvp(cod):
    """ Rota para excluir um PVP. """
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM pvp WHERE cod_pvp = %s", (cod,))
        conn.commit()
        cursor.close()
        conn.close()
        flash("PVP excluído com sucesso!", "sucesso")
    except mysql.connector.Error as err:
        # Captura erro se o PVP estiver em uso por uma categoria (chave estrangeira).
        flash(f"Não foi possível excluir o PVP. Verifique se ele não está em uso por uma categoria. Erro: {err}", "erro")
    return redirect(url_for('admin.pvps'))

# --- CRUD para Categorias ---
@admin_bp.route('/categorias')
@admin_required
def categorias():
    """ Lista todas as categorias de produtos. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT c.cod_categoria, c.nome_categoria, c.descricao_categoria, 
               p.nome_pvp AS pvp_nome
        FROM categoria_produto c
        LEFT JOIN pvp p ON c.pvp_categoria = p.cod_pvp
        ORDER BY c.nome_categoria ASC
    """)
    categorias = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('categorias.html', categorias=categorias)


@admin_bp.route('/categorias/cadastrar', methods=['GET', 'POST'])
@admin_required
def cadastrar_categoria():
    """ Cadastra uma nova categoria de produto. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Busca PVPs ativos para o select
    cursor.execute("SELECT cod_pvp, nome_pvp FROM pvp WHERE ativo = TRUE ORDER BY nome_pvp ASC")
    pvps = cursor.fetchall()

    if request.method == 'POST':
        nome = request.form['nome_categoria']
        descricao = request.form['descricao_categoria']
        pvp_categoria = request.form['pvp_categoria'] or None

        cursor.execute("""
            INSERT INTO categoria_produto (nome_categoria, descricao_categoria, pvp_categoria)
            VALUES (%s, %s, %s)
        """, (nome, descricao, pvp_categoria))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Categoria cadastrada com sucesso!", "sucesso")
        return redirect(url_for('admin.categorias'))

    cursor.close()
    conn.close()
    return render_template('cadastrar_categoria.html', pvps=pvps)


@admin_bp.route('/categorias/editar/<int:cod>', methods=['GET', 'POST'])
@admin_required
def editar_categoria(cod):
    """ Edita uma categoria existente. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Busca a categoria e os PVPs
    cursor.execute("SELECT * FROM categoria_produto WHERE cod_categoria = %s", (cod,))
    categoria = cursor.fetchone()
    cursor.execute("SELECT cod_pvp, nome_pvp FROM pvp WHERE ativo = TRUE ORDER BY nome_pvp ASC")
    pvps = cursor.fetchall()

    if not categoria:
        flash("Categoria não encontrada.", "erro")
        cursor.close()
        conn.close()
        return redirect(url_for('admin.categorias'))

    if request.method == 'POST':
        nome = request.form['nome_categoria']
        descricao = request.form['descricao_categoria']
        pvp_categoria = request.form['pvp_categoria'] or None

        cursor.execute("""
            UPDATE categoria_produto 
            SET nome_categoria = %s, descricao_categoria = %s, pvp_categoria = %s
            WHERE cod_categoria = %s
        """, (nome, descricao, pvp_categoria, cod))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Categoria atualizada com sucesso!", "sucesso")
        return redirect(url_for('admin.categorias'))

    cursor.close()
    conn.close()
    return render_template('editar_categoria.html', categoria=categoria, pvps=pvps)


@admin_bp.route('/categorias/excluir/<int:cod>', methods=['POST'])
@admin_required
def excluir_categoria(cod):
    """ Exclui uma categoria, se não estiver vinculada a produtos. """
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM categoria_produto WHERE cod_categoria = %s", (cod,))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Categoria excluída com sucesso!", "sucesso")
    except mysql.connector.Error as err:
        flash(f"Erro ao excluir a categoria. Verifique se há produtos vinculados. Detalhes: {err}", "erro")
    return redirect(url_for('admin.categorias'))


# --- CRUD para Unidades de Medida ---
@admin_bp.route('/unidades')
@admin_required
def unidades():
    """ Lista todas as unidades de medida. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("SELECT cod_unidade, sigla_unidade AS sigla, nome_unidade AS descricao FROM unidade_medida ORDER BY sigla_unidade ASC")
    lista_unidades = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('unidades.html', unidades=lista_unidades)


@admin_bp.route('/unidades/cadastrar', methods=['GET', 'POST'])
@admin_required
def cadastrar_unidade():
    """ Cadastra uma nova unidade de medida. """
    if request.method == 'POST':
        sigla = request.form['sigla'].strip().upper()
        descricao = request.form.get('descricao') or None

        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        # Evita duplicar siglas
        cursor.execute("SELECT cod_unidade FROM unidade_medida WHERE sigla_unidade = %s", (sigla,))
        if cursor.fetchone():
            flash("Sigla já cadastrada.", "erro")
            cursor.close()
            conn.close()
            return redirect(url_for('admin.unidades'))

        cursor.execute("INSERT INTO unidade_medida (sigla_unidade, nome_unidade) VALUES (%s, %s)", (sigla, descricao))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Unidade de medida cadastrada com sucesso!", "sucesso")
        return redirect(url_for('admin.unidades'))

    return render_template('cadastrar_unidade.html')


@admin_bp.route('/unidades/editar/<int:cod>', methods=['GET', 'POST'])
@admin_required
def editar_unidade(cod):
    """ Edita uma unidade de medida. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    cursor.execute("SELECT cod_unidade, nome_unidade, sigla_unidade FROM unidade_medida WHERE cod_unidade = %s", (cod,))
    unidade = cursor.fetchone()
    if not unidade:
        cursor.close()
        conn.close()
        flash("Unidade não encontrada.", "erro")
        return redirect(url_for('admin.unidades'))

    if request.method == 'POST':
        sigla = request.form['sigla'].strip()
        nome = request.form['nome'].strip()
        cursor.execute("UPDATE unidade_medida SET sigla_unidade=%s, nome_unidade=%s WHERE cod_unidade=%s", (sigla, nome, cod))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Unidade atualizada com sucesso!", "sucesso")
        return redirect(url_for('admin.unidades'))

    cursor.close()
    conn.close()
    return render_template('editar_unidade.html', unidade=unidade)


@admin_bp.route('/unidades/excluir/<int:cod>', methods=['POST'])
@admin_required
def excluir_unidade(cod):
    """ Exclui uma unidade, se não estiver em uso por produtos. """
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM unidade_medida WHERE cod_unidade = %s", (cod,))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Unidade excluída com sucesso!", "sucesso")
    except mysql.connector.Error as err:
        flash(f"Erro ao excluir a unidade. Verifique se há produtos vinculados. Detalhes: {err}", "erro")
    return redirect(url_for('admin.unidades'))


# --- CRUD para Produtos ---
@admin_bp.route('/produtos')
@admin_required
def produtos():
    """ Lista todos os produtos com suas unidades, categorias e pvp. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)
    cursor.execute("""
        SELECT p.cod_produto, p.nome_produto, p.descricao_produto, p.preco_compra, p.preco_venda,
               p.quantidade, p.codigo_barras, p.ativo, p.data_criacao,
               u.sigla_unidade AS unidade_sigla, u.nome_unidade AS unidade_descricao,
               c.nome_categoria AS categoria_nome,
               pv.nome_pvp AS pvp_nome
        FROM produto p
        LEFT JOIN unidade_medida u ON p.cod_unidade = u.cod_unidade
        LEFT JOIN categoria_produto c ON p.cod_categoria = c.cod_categoria
        LEFT JOIN pvp pv ON p.cod_pvp = pv.cod_pvp
        ORDER BY p.nome_produto ASC
    """)
    lista_produtos = cursor.fetchall()
    cursor.close()
    conn.close()
    return render_template('produtos.html', produtos=lista_produtos)


@admin_bp.route('/produtos/cadastrar', methods=['GET', 'POST'])
@admin_required
def cadastrar_produto():
    """ Cadastra um novo produto (usa cod_unidade). """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Buscar unidades, categorias e pvps para popular selects
    cursor.execute("SELECT cod_unidade, sigla_unidade AS sigla, nome_unidade AS descricao FROM unidade_medida ORDER BY sigla_unidade ASC")
    unidades = cursor.fetchall()
    cursor.execute("SELECT cod_categoria, nome_categoria FROM categoria_produto ORDER BY nome_categoria ASC")
    categorias = cursor.fetchall()
    cursor.execute("SELECT cod_pvp, nome_pvp FROM pvp WHERE ativo = TRUE ORDER BY nome_pvp ASC")
    pvps = cursor.fetchall()

    # Detecta colunas em runtime para decidir como gravar a unidade
    prod_has_cod_unidade = table_has_column('produto', 'cod_unidade')
    prod_has_unidade_medida = False if prod_has_cod_unidade else table_has_column('produto', 'unidade_medida')

    if request.method == 'POST':
        nome = request.form['nome_produto']
        descricao = request.form.get('descricao_produto') or None
        preco_compra = request.form.get('preco_compra') or 0
        preco_venda = request.form.get('preco_venda') or 0
        quantidade = request.form.get('quantidade') or 0
        cod_unidade = request.form.get('cod_unidade') or None
        codigo_barras = request.form.get('codigo_barras') or None
        cod_categoria = request.form.get('cod_categoria') or None
        cod_pvp = request.form.get('cod_pvp') or None

        cursor_insert = conn.cursor()
        if prod_has_cod_unidade:
            # Insere usando a FK cod_unidade
            query = """
                INSERT INTO produto (nome_produto, descricao_produto, preco_compra, preco_venda,
                                     quantidade, cod_unidade, codigo_barras, ativo, cod_categoria, cod_pvp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor_insert.execute(query, (nome, descricao, preco_compra, preco_venda, quantidade,
                                          cod_unidade, codigo_barras, True, cod_categoria, cod_pvp))
        elif prod_has_unidade_medida:
            # Converte o cod_unidade selecionado para a sigla antes de inserir no campo unidade_medida
            unidade_sigla = None
            if cod_unidade:
                tmp = conn.cursor()
                tmp.execute("SELECT sigla_unidade FROM unidade_medida WHERE cod_unidade = %s", (cod_unidade,))
                r = tmp.fetchone()
                tmp.close()
                unidade_sigla = r[0] if r else None

            query = """
                INSERT INTO produto (nome_produto, descricao_produto, preco_compra, preco_venda,
                                     quantidade, unidade_medida, codigo_barras, ativo, cod_categoria, cod_pvp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor_insert.execute(query, (nome, descricao, preco_compra, preco_venda, quantidade,
                                          unidade_sigla, codigo_barras, True, cod_categoria, cod_pvp))
        else:
            # Não há coluna de unidade: grava sem campo de unidade
            query = """
                INSERT INTO produto (nome_produto, descricao_produto, preco_compra, preco_venda,
                                     quantidade, codigo_barras, ativo, cod_categoria, cod_pvp)
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s)
            """
            cursor_insert.execute(query, (nome, descricao, preco_compra, preco_venda, quantidade,
                                          codigo_barras, True, cod_categoria, cod_pvp))

        conn.commit()
        cursor_insert.close()
        cursor.close()
        conn.close()
        flash("Produto cadastrado com sucesso!", "sucesso")
        return redirect(url_for('admin.produtos'))

    cursor.close()
    conn.close()
    return render_template('cadastrar_produto.html', unidades=unidades, categorias=categorias, pvps=pvps)


@admin_bp.route('/produtos/editar/<int:cod>', methods=['GET', 'POST'])
@admin_required
def editar_produto(cod):
    """ Edita um produto existente. """
    conn = mysql.connector.connect(**db_config)
    cursor = conn.cursor(dictionary=True)

    # Buscar produto, unidades, categorias e pvps
    cursor.execute("SELECT * FROM produto WHERE cod_produto = %s", (cod,))
    produto = cursor.fetchone()
    # Detecta colunas para saber como ler/ajustar a unidade
    prod_has_cod_unidade = table_has_column('produto', 'cod_unidade')
    prod_has_unidade_medida = False if prod_has_cod_unidade else table_has_column('produto', 'unidade_medida')
    # Se produto não tiver cod_unidade mas tiver unidade_medida (sigla),
    # converte a sigla em cod_unidade para uso nos templates (pre-fill)
    if produto and (not prod_has_cod_unidade) and prod_has_unidade_medida:
        sigla = produto.get('unidade_medida') if isinstance(produto, dict) else None
        if sigla:
            tmp = conn.cursor()
            tmp.execute("SELECT cod_unidade FROM unidade_medida WHERE sigla_unidade = %s", (sigla,))
            r = tmp.fetchone()
            tmp.close()
            if r and isinstance(produto, dict):
                produto['cod_unidade'] = r[0]
    cursor.execute("SELECT cod_unidade, sigla_unidade AS sigla, nome_unidade AS descricao FROM unidade_medida ORDER BY sigla_unidade ASC")
    unidades = cursor.fetchall()
    cursor.execute("SELECT cod_categoria, nome_categoria FROM categoria_produto ORDER BY nome_categoria ASC")
    categorias = cursor.fetchall()
    cursor.execute("SELECT cod_pvp, nome_pvp FROM pvp WHERE ativo = TRUE ORDER BY nome_pvp ASC")
    pvps = cursor.fetchall()

    if not produto:
        cursor.close()
        conn.close()
        flash("Produto não encontrado.", "erro")
        return redirect(url_for('admin.produtos'))

    if request.method == 'POST':
        nome = request.form['nome_produto']
        descricao = request.form.get('descricao_produto') or None
        preco_compra = request.form.get('preco_compra') or 0
        preco_venda = request.form.get('preco_venda') or 0
        quantidade = request.form.get('quantidade') or 0
        cod_unidade = request.form.get('cod_unidade') or None
        codigo_barras = request.form.get('codigo_barras') or None
        cod_categoria = request.form.get('cod_categoria') or None
        cod_pvp = request.form.get('cod_pvp') or None

        cursor_update = conn.cursor()
        if prod_has_cod_unidade:
            update_query = """
                UPDATE produto SET nome_produto=%s, descricao_produto=%s, preco_compra=%s,
                                    preco_venda=%s, quantidade=%s, cod_unidade=%s,
                                    codigo_barras=%s, cod_categoria=%s, cod_pvp=%s
                WHERE cod_produto = %s
            """
            cursor_update.execute(update_query, (nome, descricao, preco_compra, preco_venda,
                                                 quantidade, cod_unidade, codigo_barras, cod_categoria, cod_pvp, cod))
        elif prod_has_unidade_medida:
            # Converte cod_unidade selecionado para sigla e atualiza campo unidade_medida
            unidade_sigla = None
            if cod_unidade:
                tmp = conn.cursor()
                tmp.execute("SELECT sigla_unidade FROM unidade_medida WHERE cod_unidade = %s", (cod_unidade,))
                r = tmp.fetchone()
                tmp.close()
                unidade_sigla = r[0] if r else None

            update_query = """
                UPDATE produto SET nome_produto=%s, descricao_produto=%s, preco_compra=%s,
                                    preco_venda=%s, quantidade=%s, unidade_medida=%s,
                                    codigo_barras=%s, cod_categoria=%s, cod_pvp=%s
                WHERE cod_produto = %s
            """
            cursor_update.execute(update_query, (nome, descricao, preco_compra, preco_venda,
                                                 quantidade, unidade_sigla, codigo_barras, cod_categoria, cod_pvp, cod))
        else:
            # Sem coluna de unidade: atualiza sem esse campo
            update_query = """
                UPDATE produto SET nome_produto=%s, descricao_produto=%s, preco_compra=%s,
                                    preco_venda=%s, quantidade=%s,
                                    codigo_barras=%s, cod_categoria=%s, cod_pvp=%s
                WHERE cod_produto = %s
            """
            cursor_update.execute(update_query, (nome, descricao, preco_compra, preco_venda,
                                                 quantidade, codigo_barras, cod_categoria, cod_pvp, cod))

        conn.commit()
        cursor_update.close()
        cursor.close()
        conn.close()
        flash("Produto atualizado com sucesso!", "sucesso")
        return redirect(url_for('admin.produtos'))

    cursor.close()
    conn.close()
    return render_template('editar_produto.html', produto=produto, unidades=unidades, categorias=categorias, pvps=pvps)


@admin_bp.route('/produtos/excluir/<int:cod>', methods=['POST'])
@admin_required
def excluir_produto(cod):
    """ Exclui um produto. """
    try:
        conn = mysql.connector.connect(**db_config)
        cursor = conn.cursor()
        cursor.execute("DELETE FROM produto WHERE cod_produto = %s", (cod,))
        conn.commit()
        cursor.close()
        conn.close()
        flash("Produto excluído com sucesso!", "sucesso")
    except mysql.connector.Error as err:
        flash(f"Erro ao excluir produto: {err}", "erro")
    return redirect(url_for('admin.produtos'))



# =====================================================================
# SEÇÃO 6: REGISTRO DO BLUEPRINT E EXECUÇÃO
# Finaliza a configuração e inicia a aplicação.
# =====================================================================

# Registra o blueprint administrativo na aplicação principal para que as rotas funcionem.
app.register_blueprint(admin_bp)

# Bloco de execução principal: só roda o servidor se o script for executado diretamente.
if __name__ == '__main__':
    # `debug=True` ativa o modo de depuração, que recarrega o servidor a cada alteração
    # e mostra mensagens de erro detalhadas no navegador. É muito útil para desenvolvimento.
    # Lembre-se de desativar (mudar para False) em um ambiente de produção.
    app.run(debug=True)
