#################### SQL ########################

CREATE TABLE usuario (
    cod_usuario INT AUTO_INCREMENT PRIMARY KEY,
    nome_usuario VARCHAR(100) NOT NULL,
    username_usuario VARCHAR(100) UNIQUE NOT NULL,
    email_usuario VARCHAR(100) UNIQUE NOT NULL,
    password_usuario VARCHAR(255) NOT NULL,
    foto_usuario VARCHAR(100),  -- arquivo da imagem do usuário
    conta_ativa BOOLEAN NOT NULL DEFAULT TRUE,
    criacao_usuario TIMESTAMP DEFAULT CURRENT_TIMESTAMP, -- Data da criação do usuário
    tipo_usuario INT NOT NULL  -- 1 = Admin, 2 = Usuário      
);
-- 2. Tabela de PVP
CREATE TABLE pvp (
    cod_pvp INT AUTO_INCREMENT PRIMARY KEY,
    nome_pvp VARCHAR(100) NOT NULL,            -- Nome ou descrição do PVP
    percentual DECIMAL(5,2) NOT NULL,         -- Percentual de aumento (ex: 1.20 para 20%)
    tipo_pvp ENUM('global', 'categoria') NOT NULL,  -- Tipo: 'global' ou 'categoria'
    data_inicio TIMESTAMP DEFAULT CURRENT_TIMESTAMP,  -- Data de início
    data_fim DATETIME DEFAULT NULL,           -- Use DATETIME em vez de TIMESTAMP para permitir NULL
    ativo BOOLEAN NOT NULL DEFAULT TRUE    -- Se o PVP está ativo
);


-- 1. Tabela de Categorias de Produtos
CREATE TABLE categoria_produto (
    cod_categoria INT AUTO_INCREMENT PRIMARY KEY,
    nome_categoria VARCHAR(100) NOT NULL,
    pvp_categoria INT NOT NULL,  -- PVP padrão (ex: 1.20 para 20% de lucro)
    descricao_categoria TEXT,
    FOREIGN KEY (pvp_categoria) REFERENCES pvp(cod_pvp)
);





-- 3. Tabela de Produtos
-- Tabela de Unidades de Medida

CREATE TABLE `unidade_medida` (
  `cod_unidade` int(11) NOT NULL,
  `nome_unidade` varchar(50) NOT NULL,
  `sigla_unidade` varchar(10) NOT NULL
) ENGINE=InnoDB DEFAULT CHARSET=latin1 COLLATE=latin1_swedish_ci;

--
-- Despejando dados para a tabela `unidade_medida`
--



CREATE TABLE produto (
    cod_produto INT AUTO_INCREMENT PRIMARY KEY,
    nome_produto VARCHAR(100) NOT NULL,
    descricao_produto TEXT,
    preco_compra DECIMAL(10,2) NOT NULL,  -- Preço de compra
    preco_venda DECIMAL(10,2) NOT NULL,   -- Preço de venda
    quantidade INT NOT NULL DEFAULT 0,    -- Quantidade em estoque
    cod_unidade INT NOT NULL,              -- Referência para unidade de medida
    codigo_barras VARCHAR(13) UNIQUE NOT NULL,  -- Código de barras
    ativo BOOLEAN NOT NULL DEFAULT TRUE,  -- Produto ativo ou não
    cod_categoria INT NOT NULL,           -- Categoria do produto
    cod_pvp INT NOT NULL,                 -- Relacionamento com PVP
    data_criacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (cod_categoria) REFERENCES categoria_produto(cod_categoria),  -- Relacionamento com a categoria
    FOREIGN KEY (cod_pvp) REFERENCES pvp(cod_pvp),  -- Relacionamento com o PVP
    FOREIGN KEY (cod_unidade) REFERENCES unidade_medida(cod_unidade)
);




-- 5. Tabela de Vendas
CREATE TABLE venda (
    cod_venda INT AUTO_INCREMENT PRIMARY KEY,
    cod_usuario INT NOT NULL,
    data_venda TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    total DECIMAL(10,2) NOT NULL,
    FOREIGN KEY (cod_usuario) REFERENCES usuario(cod_usuario)
);

-- 6. Tabela de Itens da Venda (relaciona os produtos vendidos com a venda)
CREATE TABLE item_venda (
    cod_item INT AUTO_INCREMENT PRIMARY KEY,
    cod_venda INT NOT NULL,
    cod_produto INT NOT NULL,
    quantidade INT NOT NULL,
    preco_unitario DECIMAL(10,2) NOT NULL, -- Preço de venda do produto
    FOREIGN KEY (cod_venda) REFERENCES venda(cod_venda),
    FOREIGN KEY (cod_produto) REFERENCES produto(cod_produto)
);

-- Trigger para reduzir o estoque após a venda
DELIMITER $$
CREATE TRIGGER after_venda_insert
AFTER INSERT ON item_venda
FOR EACH ROW
BEGIN
    UPDATE produto 
    SET quantidade = quantidade - NEW.quantidade
    WHERE cod_produto = NEW.cod_produto;
END;
$$
DELIMITER ;

-- 7. Tabela de Caixa (Movimentações de entrada e saída de dinheiro)
CREATE TABLE caixa (
    cod_caixa INT AUTO_INCREMENT PRIMARY KEY,
    tipo ENUM('entrada', 'saida') NOT NULL,
    valor DECIMAL(10,2) NOT NULL,
    descricao TEXT,
    data_movimentacao TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    cod_usuario INT NOT NULL,  -- Relaciona a movimentação de caixa ao usuário do caixa
    FOREIGN KEY (cod_usuario) REFERENCES usuario(cod_usuario)
);





-- =====================================================================
-- INSERÇÃO DE DADOS INICIAIS
-- Execute os blocos na ordem em que aparecem.
-- =====================================================================

-- Bloco 1: Inserção na tabela PVP
-- Primeiro, criamos todos os registros de PVP para que eles recebam um ID.

INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Alimentos Básicos', 1.20, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Carnes e Aves', 1.25, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Frios e Embutidos', 1.30, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Laticínios', 1.25, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Padaria e Confeitaria', 1.35, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Hortifrúti', 1.15, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Bebidas', 1.40, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Limpeza', 1.30, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Higiene Pessoal', 1.30, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Pet Shop', 1.35, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Congelados', 1.25, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Enlatados e Conservas', 1.20, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Cereais e Matinais', 1.25, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Produtos Naturais', 1.30, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Utilidades Domésticas', 1.40, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Bazar', 1.45, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Perfumaria', 1.50, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Infantil', 1.35, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Mercearia', 1.20, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Importados', 1.60, 'categoria', TRUE);
INSERT INTO pvp (nome_pvp, percentual, tipo_pvp, ativo) VALUES ('PVP Global Padrão', 1.20, 'global', TRUE);

-- Bloco 2: Inserção na tabela Categoria_Produto
-- Agora, inserimos as categorias, referenciando o ID do PVP criado acima.
-- (Assumindo que os IDs dos PVPs foram gerados em ordem de 1 a 21)

INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Alimentos Básicos', 1, 'Arroz, feijão, macarrão, farinha, açúcar, sal e outros itens essenciais.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Carnes e Aves', 2, 'Carne bovina, suína, frango, peixe e derivados.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Frios e Embutidos', 3, 'Presunto, queijo, mortadela, salsicha, salame, etc.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Laticínios', 4, 'Leite, iogurte, manteiga, requeijão, creme de leite.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Padaria e Confeitaria', 5, 'Pães, bolos, biscoitos, doces e salgados.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Hortifrúti', 6, 'Frutas, verduras, legumes e ovos.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Bebidas', 7, 'Refrigerantes, sucos, água, cervejas, vinhos e destilados.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Limpeza', 8, 'Detergente, sabão, desinfetante, água sanitária, esponjas.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Higiene Pessoal', 9, 'Sabonetes, shampoos, cremes, papel higiênico, absorventes.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Pet Shop', 10, 'Rações, petiscos, produtos de higiene para animais.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Congelados', 11, 'Produtos congelados como pizzas, lasanhas, vegetais, carnes.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Enlatados e Conservas', 12, 'Milho, ervilha, sardinha, molho de tomate, palmito.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Cereais e Matinais', 13, 'Cereais, granolas, aveia, achocolatados.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Produtos Naturais', 14, 'Orgânicos, integrais, sem glúten, sem lactose.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Utilidades Domésticas', 15, 'Panos, baldes, vassouras, utensílios de cozinha.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Bazar', 16, 'Pilhas, velas, ferramentas, itens diversos.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Perfumaria', 17, 'Perfumes, desodorantes, maquiagens, cosméticos.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Infantil', 18, 'Fraldas, papinhas, produtos para bebês e crianças.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Mercearia', 19, 'Óleos, temperos, molhos, farinhas especiais.');
INSERT INTO categoria_produto (nome_categoria, pvp_categoria, descricao_categoria) VALUES ('Importados', 20, 'Produtos estrangeiros, gourmet ou diferenciados.');

-- Bloco 3: Inserção de Unidades de Medida (valores iniciais)
INSERT INTO `unidade_medida` (`cod_unidade`, `nome_unidade`, `sigla_unidade`) VALUES
(1, 'Quilograma', 'kg'),
(2, 'Grama', 'g'),
(3, 'Litro', 'L'),
(4, 'Mililitro', 'mL'),
(5, 'Metro', 'm'),
(6, 'Centímetro', 'cm'),
(7, 'Unidade', 'un'),
(8, 'Caixa', 'cx'),
(9, 'Pacote', 'pct'),
(10, 'Dúzia', 'dz'),
(11, 'Par', 'par'),
(12, 'Tonelada', 't'),
(13, 'Galão', 'gal'),
(14, 'Barril', 'bbl'),
(15, 'Fardo', 'fd'),
(16, 'Cartela', 'ctl'),
(17, 'Frasco', 'fr'),
(18, 'Garrafa', 'gf'),
(19, 'Lata', 'lt'),
(20, 'Saco', 'sc'),
(21, 'Envelope', 'env'),
(22, 'Bandeja', 'bdj'),
(23, 'Pote', 'pt'),
(24, 'Vidro', 'vd'),
(25, 'Bloco', 'bl'),
(26, 'Kit', 'kit');
