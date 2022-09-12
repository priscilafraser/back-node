const express = require('express')
const app = express()
const pg = require('pg')
const port = process.env.PORT   
const bcrypt = require('bcrypt')
const jwt = require('jsonwebtoken');  //token
const cors = require('cors')


//para pegar os dados do formulario
app.use(cors())
app.use(express.urlencoded({ extended: false }))
app.use(express.json())


const consStr = process.env.DATABASE_URL
const pool = new pg.Pool({ connectionString: consStr, ssl: { rejectUnauthorized: false} }) 
//, ssl: { rejectUnauthorized: false}

///////LOGIN
app.post('/login', (req,res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({message: 'Conexão não autorizada'})
        }       
        var sql = 'select * from fornecedor where email = $1'
        let dados = [req.body.email]
        client.query(sql, dados, (error, result) => {
            if(error) {
                return res.status(500).send({ message: 'Erro ao selecionar fornecedor'})
            }
            if(result.rowCount>0) { 
                bcrypt.compare(req.body.senha, result.rows[0].senha, (error, results) => {
                    if(error) {
                        return res.status(401).send({
                            message: 'Falha de autenticação'
                        })
                    }
                    if(results) {
                        let token = jwt.sign({
                            id: result.rows[0].id,
                            razaosocial: result.rows[0].razaosocial,                           
                            cnpj:result.rows[0].cnpj,                          
                            telefone: result.rows[0].telefone,                         
                            email: result.rows[0].email,
                            cep: result.rows[0].cep,
                            logradouro: result.rows[0].logradouro,
                            numero: result.rows[0].numero,
                            complemento: result.rows[0].complemento,
                            bairro: result.rows[0].bairro,
                            cidade: result.rows[0].cidade,
                            estado: result.rows[0].estado,
                            perfil: result.rows[0].perfil
                        }, 'chave secreta', {expiresIn: '1h'})
                        return res.status(200).send({
                        message: 'Login realizado com sucesso',
                        token: token,
                        razaosocial: result.rows[0].razaosocial,
                        idfornecedor: result.rows[0].id
                        })
                    } 
                    return res.status(401).send({message: 'Senha não confere'})                   
                })
            }  
            
            var sql2 = 'select * from cliente where email = $1'
            let dados2 = [req.body.email]
            client.query(sql2, dados2, (error, result) => {
                if(error) {
                    return res.status(500).send({ message: 'Erro ao selecionar cliente'})
                }
                
                if(result.rowCount>0) { 
                    bcrypt.compare(req.body.senha, result.rows[0].senha, (error, results) => {
                        if(error) {
                            return res.status(401).send({
                                message: 'Falha de autenticação'
                            })
                        }
                        if(results) {
                            let token = jwt.sign({
                                nome: result.rows[0].nome,
                                telefone: result.rows[0].telefone,
                                email: result.rows[0].email,
                                cep: result.rows[0].cep,
                                logradouro: result.rows[0].logradouro,
                                numero: result.rows[0].numero,
                                complemento: result.rows[0].complemento,
                                bairro: result.rows[0].bairro,
                                cidade: result.rows[0].cidade,
                                estado: result.rows[0].estado,
                                perfil: result.rows[0].perfil
                            }, 'chave secreta', {expiresIn: '1h'})     
                            return res.status(200).send({
                            message: 'Login realizado com sucesso',
                            token: token
                            })
                        } 
                        return res.status(401).send({message: 'Senha não confere'})
                    })
                } else {
                    var sql3 = 'select * from adm where email = $1'
                    let dados3 = [req.body.email]
                    client.query(sql3, dados3, (error, result) => {
                        if(error) {
                            return res.status(500).send({ message: 'Erro ao selecionar ADM'})
                        }
                        
                        if(result.rowCount>0) {
                            bcrypt.compare(req.body.senha, result.rows[0].senha, (error, results) => {
                                if(error) {
                                    return res.status(401).send({
                                        message: 'Falha de autenticação'
                                    })
                                }
                                if(results) {
                                    let token = jwt.sign({
                                        email: result.rows[0].email,
                                        perfil: result.rows[0].perfil
                                    }, 'chave secreta', {expiresIn: '1h'})     
                                    return res.status(200).send({
                                    message: 'Login realizado com sucesso',
                                    token: token
                                    })
                                } 
                                return res.status(401).send({message: 'Senha não confere'})
                            })

                            if(result.rowCount!=1) {
                                return res.status(404).send({
                                    message: 'Usuário não encontrado'
                                })
                            }
                        }                       
                    })
                }
            })            
        })        
        release()
    })
})



////////CADASTRO LOJISTA
app.post('/cadastro-fornecedor', (req, res) => {
    pool.connect((err, client, release) => {
        if (err) {
            return res.status(401).send({
                message: 'Conexão não autorizada'
            })
        }
        var sql = 'select * from fornecedor where cnpj=$1'
        let dados1 = [req.body.cnpj]
        client.query(sql, dados1, (err, result) => {
            if(result.rowCount > 0) {
                return res.status(500).send({message:'Fornecedor já cadastrado'})
            } else {
                bcrypt.hash(req.body.senha, 10, (error, hash) => {
                    if(error) {
                        return res.status(500).send({message: 'Erro de autenticação'})
                    }       
                    var sql = 'insert into fornecedor (razaosocial, cnpj, telefone, email, cep, logradouro, numero, complemento, bairro,cidade, estado, perfil, senha) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)'
                    let dados = [req.body.razaosocial, req.body.cnpj, req.body.telefone, req.body.email, req.body.cep, req.body.logradouro, req.body.numero, req.body.complemento, req.body.bairro,req.body.cidade, req.body.estado, req.body.perfil, hash]
                    client.query(sql, dados, (error, result) => {
                        if(error) {
                            return res.status(500).send({
                                message: 'Erro ao inserir fornecedor',
                                erro: error.message
                            })
                        }
                        return res.status(201).send({
                            message: 'Fornecedor cadastrado com sucesso'
                        })
                    })
                })
            }
        })
        release()
    })
})


/////////////////////////////////////////////////////
/////////CADASTRO USUARIO
app.post('/cadastro-cliente', (req, res) => {
    pool.connect((err, client, release) => {
        if (err) {
            return res.status(401).send({
                message: 'Conexão não autorizada'
            })
        }
        var sql = 'select * from cliente where email=$1'
        let dados1 = [req.body.email]
        client.query(sql, dados1, (err, result) => {
            if(result.rowCount > 0) {
                return res.status(500).send({message:'Cliente já cadastrado'})
            } else {
                bcrypt.hash(req.body.senha, 10, (error, hash) => {
                    if(error) {
                        return res.status(500).send({message: 'Erro de autenticação'})
                    }
        
                    var sql = 'insert into cliente (nome, cpf, telefone, email, cep, logradouro, numero, complemento, bairro, cidade, estado, perfil, senha) values ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)'
                    let dados = [req.body.nome, req.body.cpf, req.body.telefone, req.body.email, req.body.cep, req.body.logradouro, req.body.numero, req.body.complemento, req.body.bairro, req.body.cidade, req.body.estado, req.body.perfil, hash]
                    client.query(sql, dados, (error, result) => {
                        if(error) {
                            return res.status(500).send({
                                message: 'Erro ao inserir cliente', erro: error.message
                            })
                        }
                        return res.status(201).send({
                            message: 'Cliente cadastrado com sucesso'
                        })
                    })
                })
            }
        })
        release()
    })
})

/////////////////////////////
////////CADASTRO ADMINISTRADOR
app.post('/cadastro-adm', (req, res) => {
    pool.connect((err, client, release) => {
        if (err) {
            return res.status(401).send({
                message: 'Conexão não autorizada'
            })
        }
        var sql = 'select * from adm where perfil=$1'
        let dados1 = [req.body.perfil]
        client.query(sql, dados1, (err, result) => {
            if(result.rowCount > 0) {
                return res.status(500).send({message:'ADM já cadastrado'})
            } else {
                bcrypt.hash(req.body.senha, 10, (error, hash) => {
                    if(error) {
                        return res.status(500).send({message: 'Erro de autenticação', erro: error.message})
                    }       
                    var sql = 'insert into adm (email, perfil, senha) values ($1, $2, $3)'
                    let dados = [req.body.email, req.body.perfil, hash]
                    client.query(sql, dados, (error, result) => {
                        if(error) {
                            return res.status(500).send({
                                message: 'Erro ao inserir ADM',
                                erro: error.message
                            })
                        }
                        return res.status(201).send({
                            message: 'ADM cadastrado com sucesso'
                        })
                    })
                })
            }
        })
        release()
    })
})


////////////////CONTATO
app.post('/contato', (req, res) => {
    pool.connect((err, client, release) => {
        if (err) {
            return res.status(401).send({
                message: 'Conexão não autorizada'
            })
        }

        var sql = 'insert into contato (nome, email, telefone, assunto, mensagem) values ($1, $2, $3, $4, $5)'
        let dados = [req.body.nome, req.body.email, req.body.telefone, req.body.assunto, req.body.mensagem]
        client.query(sql, dados, (error, result) => {
            if(error) {
                return res.status(500).send({
                    message: 'Erro ao enviar mensagem'
                })
            }
            return res.status(201).send({
                message: 'Mensagem enviada com sucesso'
            })
        })
        release()
    })
})

app.post('/obterLojista', (req, res) => {
    pool.connect((err, client, release) => {
        if (err) {
            return res.status(401).send({
                message: 'Conexão nao autorizada'
            })
        }
        var token = req.body.token
        let tokenDecriptado = jwt.verify(token, 'chave secreta')
        let sql = 'select * from fornecedor where id = $1'
        let dados = [tokenDecriptado.id]
        client.query(sql, dados, (error, result) => {
            if(error) {
                return res.status(500).send({
                    message: 'Erro ao enviar mensagem'
                })
            }
            return res.status(200).send(result.rows[0])
        })
        release()

    })
})

app.post('/alterarLojista', (req, res) => {
    pool.connect((err, client, release) => {
        if (err) {
            return res.status(401).send({
                message: 'Conexão nao autorizada'
            })
        }
        console.log(req.body)
        var id = req.body.id
        let dadosFornecedor = req.body.dadosFornecedor
        let sql = `
        UPDATE fornecedor
        SET razaosocial=$1, cnpj=$2, telefone=$3, email=$4, cep=$5, logradouro=$6, numero=$7, complemento=$8, bairro=$9, estado=$10, cidade=$11
        WHERE id = $12
    `
        let dados = [dadosFornecedor.razaosocial, dadosFornecedor.cnpj, dadosFornecedor.telefone, dadosFornecedor.email,dadosFornecedor.cep, dadosFornecedor.logradouro,  dadosFornecedor.numero, dadosFornecedor.complemento, dadosFornecedor.bairro, dadosFornecedor.estado,dadosFornecedor.cidade, id]
        client.query(sql, dados, (error, result) => {
            if(error) {
                return res.status(500).send({
                    message: 'Erro ao enviar mensagem'
                })
            }
            return res.status(200).send(result.rows[0])
        })
        release()
    })
})

app.post('/cadastro-produto', (req, res) => {
    pool.connect((err, client, release) => {
        try {

        if (err) {
            console.log(err)
            return res.status(401).send({
                message: 'Conexão não autorizada'
            })
        }
        var dadosProduto = req.body.dadosProduto
        let idfornecedor = parseInt(req.body.idfornecedor)
        let sql = 'insert into produto (produtos, idtipoproduto, idcategoria) values ($1, $2, $3) RETURNING idproduto'
        let dados = [dadosProduto.produtos, dadosProduto.idtipoproduto, dadosProduto.idcategoria, ]
        client.query(sql, dados, (error, result) => {
            let idproduto = result.rows[0].idproduto
            if(error) {
                return res.status(500).send({
                    message: 'Erro ao inserir produto',
                    erro: error.message
                })
            }
            var sqlLigacaoFornecdor = 'insert into ligacaofornecedorproduto (idproduto, idfornecedor, preco, descricao) values ($1, $2, $3, $4)'
            let dadosLigacaoFornecedor = [idproduto, idfornecedor, dadosProduto.preco, dadosProduto.produtos]
            console.log(dadosLigacaoFornecedor)
            client.query(sqlLigacaoFornecdor, dadosLigacaoFornecedor, (error, result) => {
                console.log(error)
                return res.status(201).send({
                    message: 'Produto cadastrado com sucesso'
                })

            })
        
        })
    }
    finally {
        release()
    }
    })
})

app.post('/cadastro-servico', (req, res) => {
    pool.connect((err, client, release) => {
        if (err) {
            return res.status(401).send({
                message: 'Conexão não autorizada'
            })
        }
        var dadosServico = req.body.dadosServico
        let idfornecedor = req.body.idfornecedor
        let sql = 'insert into servico (servicos,horarioInicial, horarioFinal, preco, idcategoria, idtiposervico) values ($1, $2, $3, $4, $5, $6)  RETURNING idservico'
        let dados = [dadosServico.servicos, dadosServico.horarioInicial, dadosServico.horarioFinal, dadosServico.preco, dadosServico.idcategoria, dadosServico.idtiposervico]
        client.query(sql, dados, (error, result) => {
            if(error) {
                return res.status(500).send({
                    message: 'Erro ao inserir servico',
                    erro: error.message
                })
            }
            var idservico = result.rows[0].idservico
            console.log(idservico)
            let queryLigacaoFornecedorServico = "insert into ligacaofornecedorservico (idservico, idfornecedor) values ($1, $2)"
            var dadosParaLigacao = [idservico, idfornecedor]
            client.query(queryLigacaoFornecedorServico, dadosParaLigacao, (error, result) => {
                if(error) {
                    return res.status(500).send({
                        message: 'Erro ao inserir servico',
                        erro: error.message
                    })
                }
            })
            release()
            return res.status(201).send({
                message: 'servico cadastrado com sucesso'
            })
        })
    })
})

////////////////////////////////////////////////////
///////////////

app.post('/obter-produtos-do-fornecedor', (req, res) => {
    pool.connect((err, client, release) => {
        try{

            if (err) {
                return res.status(401).send({
                    message: 'Conexão nao autorizada'
                })
            }
            var sql = `
            select produto.*, categoria.descricao as categoria, ligacaofornecedorproduto.preco, ligacaofornecedorproduto.descricao as produtos, tipoproduto.produto as tipoproduto from produto join ligacaofornecedorproduto on ligacaofornecedorproduto.idproduto = produto.idproduto join categoria on categoria.id = produto.idcategoria join tipoproduto on tipoproduto.idtipoproduto = produto.idtipoproduto where ligacaofornecedorproduto.idfornecedor = $1
        `
            let dados = [req.body.idfornecedor]
            client.query(sql, dados, (error, result) => {
                if(error) {
                    return res.status(500).send({
                        message: 'Erro ao enviar mensagem'
                    })
                }
                return res.status(200).send(result.rows)
            })
        }
        finally {
            release()
    
        }
    })
})


app.post('/obter-servicos-do-fornecedor', (req, res) => {
    pool.connect((err, client, release) => {
        try{

            if (err) {
                return res.status(401).send({
                    message: 'Conexão nao autorizada'
                })
            }
            var sql = `
            select servico.*, categoria.descricao as categoria, tiposervico.servico as tiposervico from servico join ligacaofornecedorservico on ligacaofornecedorservico.idservico = servico.idservico join categoria on categoria.id = servico.idcategoria join tiposervico on tiposervico.idtiposervico = servico.idtiposervico where ligacaofornecedorservico.idfornecedor = $1
        `
            let dados = [req.body.idfornecedor]
            client.query(sql, dados, (error, result) => {
                if(error) {
                    return res.status(500).send({
                        message: 'Erro ao enviar mensagem'
                    })
                }
                return res.status(200).send(result.rows)
            })
        }
        finally {
            release()
        }
    })
})

app.get('/produtos', (req, res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({
                message: "Erro ao conectar ao database"
            })
        }
        client.query("select * from ligacaofornecedorproduto", (error, result) => {
            if(error) {
                return res.send({
                    message: 'erro ao consultar dados',
                    error: error.message
                })
            }
            return res.status(200).send(result.rows)
        })
        release()
    })
})

app.post('/deletar-servico', (req, res) => {
    pool.connect((err, client, release) => {
        try{
            var idservico = req.body.idservico;
            if (err) {
                return res.status(401).send({
                    message: 'Conexão nao autorizada'
                })
            }
            var sql = `delete from servico where idservico = $1`
            var dados = [idservico]
            client.query(sql, dados, (error, result) => {
                if(error) {
                    console.log(error)
                    return res.status(500).send({
                        message: 'Erro ao enviar mensagem'
                    })
                }
            })
            return res.status(200).send({
                message: 'Servico deletado com sucesso'
            })
        }
        finally {
            release()
        }
    })
})




app.post('/deletar-produto', (req, res) => {
    pool.connect((err, client, release) => {
        try{
            var idproduto = req.body.idproduto;
            if (err) {
                return res.status(401).send({
                    message: 'Conexão nao autorizada'
                })
            }
            var sql = `delete from produto where idproduto = $1`
            var dados = [idproduto]
            client.query(sql, dados, (error, result) => {
                if(error) {
                    console.log(error)
                    return res.status(500).send({
                        message: 'Erro ao enviar mensagem'
                    })
                }
            })
            return res.status(200).send({
                message: 'Produto deletado com sucesso'
            })
        }
        finally {
            release()
        }
    })
})


app.get('/servicos', (req, res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({
                message: "Erro ao conectar ao database"
            })
        }
        client.query("select * from servico", (error, result) => {
            if(error) {
                return res.send({
                    message: 'erro ao consultar dados',
                    error: error.message
                })
            }
            return res.status(200).send(result.rows)
        })
        release()
    })
})

app.get('/fornecedores', (req, res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({
                message: "Erro ao conectar ao database"
            })
        }
        client.query("select * from fornecedor", (error, result) => {
            if(error) {
                return res.send({
                    message: 'erro ao consultar dados',
                    error: error.message
                })
            }
            return res.status(200).send(result.rows)
        })
        release()
    })
})

app.get('/clientes', (req, res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({
                message: "Erro ao conectar ao database"
            })
        }
        client.query("select * from cliente", (error, result) => {
            if(error) {
                return res.send({
                    message: 'erro ao consultar dados',
                    error: error.message
                })
            }
            return res.status(200).send(result.rows)
        })
        release()
    })
})

app.get('/prodfor', (req, res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({
                message: "Erro ao conectar ao database"
            })
        }
        client.query("select * from ligacao_fornecedor_produto", (error, result) => {
            if(error) {
                return res.send({
                    message: 'erro ao consultar dados',
                    error: error.message
                })
            }
            return res.status(200).send(result.rows)
        })
        release()
    })
})

app.get('/prodFornecedor/:idfornecedor', (req, res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({
                message: "Erro ao conectar ao database"
            })
        }

        var sql = `select * from ligacao_fornecedor_produto where idfornecedor = $1`
        var dados = [req.params.idfornecedor]

        client.query(sql, dados, (error, result) => {
            if(error) {
                res.send({
                    message: 'erro ao consultar dados',
                    error: error.message
                })
            }
            return res.status(200).send(result.rows)
        })
        release()
    })
})


app.get('/servFornecedor/:idfornecedor', (req, res) => {
    pool.connect((err, client, release) => {
        if(err) {
            return res.status(401).send({
                message: "Erro ao conectar ao database"
            })
        }

        var sql = `select * from ligacao_fornecedor_servico where idfornecedor = $1`
        var dados = [req.params.idfornecedor]

        client.query(sql, dados, (error, result) => {
            if(error) {
                res.send({
                    message: 'erro ao consultar dados',
                    error: error.message
                })
            }
            return res.status(200).send(result.rows)
        })
        release()
    })
})



//////////////////////////////////////////////////////
app.listen(port, () => {
    console.log(`Executando em http://localhost:${port}`)
})
