package ursa

import (
	"encoding/json"
	"math/big"
	"testing"
	"unsafe"

	"github.com/stretchr/testify/assert"
)

func TestNewNonce(t *testing.T) {
	t.Run("NewNonce", func(t *testing.T) {
		n, err := NewNonce()
		assert.Empty(t, err)

		jsn, err := n.ToJSON()
		assert.NoError(t, err)

		var str string
		err = json.Unmarshal(jsn, &str)

		i := new(big.Int)
		_, ok := i.SetString(str, 10)
		assert.True(t, ok)
	})
}

func TestNonceFromJSON(t *testing.T) {
	t.Run("NonceFromJSON", func(t *testing.T) {
		n, err := NonceFromJSON("123456")
		assert.NoError(t, err)

		jsn, err := n.ToJSON()
		assert.NoError(t, err)

		var str string
		err = json.Unmarshal(jsn, &str)

		i := new(big.Int)
		_, ok := i.SetString(str, 10)
		assert.True(t, ok)
		assert.Equal(t, i.Int64(), int64(123456))
	})

	t.Run("NonceFromJSON", func(t *testing.T) {
		n, err := NonceFromJSON("should_error")
		assert.Empty(t, n)
		assert.NotEmpty(t, err)
	})

	t.Run("Pass NonceToJson", func(t *testing.T) {
		n, err := NewNonce()
		assert.Empty(t, err)
		assert.NotEmpty(t, n)


		noncePtr, err := NonceFromJson(n)
		assert.Empty(t, err)
		assert.NotEmpty(t, noncePtr)
	})
}

func TestCredentialKeyCorrectnessProofFromJSON(t *testing.T) {
	t.Run("CredentialKeyCorrectnessProofFromJSON", func(t *testing.T) {
		correctnessProof, err := CredentialKeyCorrectnessProofFromJSON("bad string")
		assert.NotEmpty(t, err)
		assert.Empty(t, correctnessProof)
	})
}

func TestBlindedCredentialSecretsCorrectnessProofFromJSON(t *testing.T) {
	t.Run("BlindedCredentialSecretsCorrectnessProofFromJSON", func(t *testing.T) {
		correctnessProof, err := BlindedCredentialSecretsCorrectnessProofFromJSON("should error")
		assert.NotEmpty(t, err)
		assert.Empty(t, correctnessProof)
	})
}

func TestBlindedCredentialSecretsFromJSON(t *testing.T) {
	t.Run("BlindedCredentialSecretsFromJSON", func(t *testing.T) {
		credentialSecrets, err := BlindedCredentialSecretsFromJSON("should error")
		assert.NotEmpty(t, err)
		assert.Empty(t, credentialSecrets)
	})
}

func TestCredentialPrivateKeyFromJSON(t *testing.T) {
	t.Run("CredentialPrivateKeyFromJSON", func(t *testing.T) {
		credPK, err := CredentialPrivateKeyFromJSON("should error")
		assert.NotEmpty(t, err)
		assert.Empty(t, credPK)
	})
	//	will test positive test case once C.ursa_cl_issuer_new_credential_def is wrapped
}

func TestCredentialPublicKeyFromJSON(t *testing.T) {
	t.Run("CredentialPublicKeyFromJSON", func(t *testing.T) {
		credPubKey, err := CredentialPublicKeyFromJSON("should error")
		assert.NotEmpty(t, err)
		assert.Empty(t, credPubKey)
	})

	t.Run("CredentialPublicKeyFromJSON", func(t *testing.T) {
		pk := `{"p_key": {
         "n": "108287889148300316626207730473335975931381324770775735724645123874260779372777494543407220823048855445706004029402240305856251416054433860231719270542455705533418503864596477511689337265606061482998569248816790582038383855525596069960821098360339043275867694682045423106821679023415276389807495664971622700038260706565018120484352261089938901024746861378694644736601450050486664386916355187017673076865314433572241059639163419427190442503909674145463092588722760454270616655228968404252436637310638323412590436524098308580854590913165383965421820813874509017896664526032381339226802962064709736184622643907804090340357",
         "r": {
           "ceeb": "20187037038427668859914876203573209361055050430543444514189897832293506755778175238171346732256410660100164427320346983366644011273508446347766938097512341439339801377711122888979184202166064198990644750071583994880717380113745002075173408907569196490245503964512718413558797577455402983421934395793123088886338080252819423491372092929720757027143947058668545481180816863687434778797493481926889624856203925427810550479749406355290923530850693823090429945291638109840097783744756643195303817525789900712008914865982622260156780333440676277105441319664551043142634888404564280113769011889304107088264261596546604853783",
           "city": "75721634893128516019874384521710264076257554056482231219845048775294501394535663394315517369318019283554208413855886846702058879010557649927062438399401912819267105394698349580305876788350449331677575377869570743178883377168894567563208441081524838062622368969056035630920467088780508647171666726376203961004973560206064554347233512519243541264321415467709892557678741280989858441508817695832849498295991383316309019072095529025299229188420195413502931973485505684925129239969212759907033917569528679087729349023391030714920047691476612293842841285065066749888501718324250850592015706115863271522046562058415842664188",
           "master_secret": "59509207097961110769904652324626973711895675792231709051606613858625146236089339814348014664396537436931694815568883540779897467160706196540764640530014192458351428717414379944857314852750501577475384443552530787595014501319013582440534346624712470531715631090453277546765271947070393250596983735599062856318814920219769097925462821596785686255078451082436429220623189066826112107057018636139035583402083323736153871588592345121241167480635423847275541782633103120309138686685381258862632578260630288315993821956700671688810892481451806627650891319064774560174566381756585190914442016883220038857602723910907777528413",
           "name": "37487641042866037327783302640799310609560155554202790862766982441729780051213662051932809950449327384215373607307848769930061359934113979804139620772902042093048430184886088289779612860379524151389319370084993718103373930504993038961822431592818846435137818187158297397206328785139569442708679457456335940786806384899117219320862153528246334140046582079212129751440754276987860969427795918783408840622986542654715435701511902419638241978840760160632322150499515780084305895351132481944623369140522304365467238079439012428502574624554957822553627244625240821700021341399776217363779004116830915551593059133800985535292",
           "state": "91853954573878257428192680426088470663679064473337471150508634642323148880724645060071348970033116392445671384996477023579407640022067361366263568390166041424806433521077479220761654801282879094143425615861895472709508356121910071872463520871506109134938144823078750446955714255318412387151451435804423314259149768327418351366283872897373978070345705698217696096440510430170818547168836244768632354954627219639879021973013845638242203717262851861461751862210213642918436136847839582868204748190928181293378222191284844462458296312186802215975043444399709700503881869487091860524246104034505689064241031832583381981583",
           "zipcode": "1912208481027416363267299795543551165428328603097258416224622086657103833593065312336974724803707958890587683917668221981010329626605079893269539204454671594522800659016594772774662058444986757118628166453620869516613080609101157743544773926003627306224792508122772366528425188167980126148649595212538168212157206995151497446907476768209247072868624465809558678725919334546146797180729864520171986346164336332635214849754726726851351476003580113861976925414257050438360379265035501412949777315900174716705800824766495814664984486816203081377917447714103786605077813523036355905791236630296613138859633589988463507189"
         },
         "rctxt": "606768556708691809250672294385129018912202920222168202044067737366226124519897036026241977790555511135296405588478049972896742351328134520808089923326200414631110373746775342978567952317393152101047693373793278225940807002175053977370223791086116317607828560721446403350558127959472569586758392955515924063873602951411511203111669710199454855673505481764547966685909569286943617580671647678446868159163787373186692932196419482223607150968026310968943702818287766441436945275273491907308864158077773058441973984577892107079569600797736927564105420312519896351073484117925496105199037411817626733069759505371834303290",
         "s": "46261171605295513523803359785260334852446466312916919654639907313035103391130249443050540969502735772108881166051311637694979351486074353077939101575388108609669653374286164399799788341850404139313666443148220167928573249678483705369785257925662138521335549557623498675759251597834680880291558103863247352789208688294060341315253223807442229803348459803338560837810036696552830086740534298298956133125311392537317922993986415230956657201261953495189059237711346890353141640403761571566184300391649130708067706709298573519713933784336416228737618227843620960146645123224729811068230585683116466037429170959835577669594",
         "z": "100575037796435700243943691767872077762220112870934582186886823285537691795467980464322681869583831432429347665667669133975628879262197248692545502086905748743995423632304369059689360454495382116638924389628546799896130668008079968423260749200925480431816778140444021097581135874096358823480704937431566913834271434378080880035702614465478985394549003527450740078010127638438842673809610113073564005959985169980061587662978274329234309998049948570801136494284842377726062084047642911007177430311933493884504451650733829453945961303725494919989506887915817649687007832321207466673596927594919855686300600431103249988571"
       }}`

		credPubKey, err := CredentialPublicKeyFromJSON(pk)
		assert.Empty(t, err)
		assert.NotEmpty(t, credPubKey)
	})
}

func TestSignCredential(t *testing.T) {
	fields := []string{"attr1", "attr2", "attr3"}
	vals := map[string]interface{}{
		"attr1": "val1",
		"attr2": "val2",
		"attr3": "val3",
	}

	sig, sigCorrectnessProof := createSignature(t, fields, vals)

	js, err := sig.ToJSON()
	assert.NoError(t, err)

	newSig, err := CredentialSignatureFromJSON(js)
	assert.NoError(t, err)
	assert.NotEmpty(t, newSig)

	err = sig.Free()
	assert.NoError(t, err)

	js, err = sigCorrectnessProof.ToJSON()
	assert.NoError(t, err)

	newCP, err := CredentialSignatureCorrectnessProofFromJSON(js)
	assert.NoError(t, err)
	assert.NotEmpty(t, newCP)

	err = sigCorrectnessProof.Free()
	assert.NoError(t, err)
}

func TestCorrectnessProofToJSON(t *testing.T) {
	var emptyProof unsafe.Pointer
	proof, err := CorrectnessProofToJSON(emptyProof)
	assert.NotEmpty(t, err)
	assert.Empty(t, proof)
}

func TestNewNonCredentialSchemaBuilder(t *testing.T) {
	t.Run("NewNonCredentialSchemaBuilder", func(t *testing.T) {
		nonBuilder, err := NewNonCredentialSchemaBuilder()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonBuilder)
	})
}

func TestNonCredentialSchemaBuilderFinalize(t *testing.T) {
	t.Run("NonCredentialSchemaBuilderFinalize", func(t *testing.T) {
		nonBuilder, _ := NewNonCredentialSchemaBuilder()
		err := nonBuilder.AddAttr("master_secret")
		assert.NoError(t, err)

		nonSchema, err := nonBuilder.Finalize()
		assert.Empty(t, err)
		assert.NotEmpty(t, nonSchema)

		err = nonSchema.Free()
		assert.NoError(t, err)
	})
}

func TestCredentialSchemaBuilderNew(t *testing.T) {
	t.Run("CredentialSchemaBuilderNew", func(t *testing.T) {
		schemaBuilder, err := NewCredentialSchemaBuilder()
		assert.Empty(t, err)
		assert.NotEmpty(t, schemaBuilder)
	})
}

func TestCredentialSchemaBuilderFinalize(t *testing.T) {
	t.Run("CredentialSchemaBuilderFinalize", func(t *testing.T) {
		builder, _ := NewCredentialSchemaBuilder()
		err := builder.AddAttr("master_secret")
		assert.NoError(t, err)

		schema, err := builder.Finalize()
		assert.Empty(t, err)
		assert.NotEmpty(t, schema)

		err = schema.Free()
		assert.NoError(t, err)
	})
}

func TestBlindCredentialSecrets(t *testing.T) {
	t.Run("happy path", func(t *testing.T) {
		var nonfields []string

		fields := []string{"attr1", "attr2", "attr3"}
		vals := map[string]interface{}{
			"attr1": "val1",
			"attr2": "val2",
			"attr3": "val3",
		}

		nonce, err := NewNonce()
		assert.NoError(t, err)

		credDef := createCredentialDefinition(t, fields, nonfields)
		blindedSecrets := createBlindedSecrets(t, credDef, nonce, vals)

		jsn, err := blindedSecrets.Handle.ToJSON()
		assert.NoError(t, err)

		m := map[string]interface{}{}
		err = json.Unmarshal(jsn, &m)
		assert.NoError(t, err)

		x, ok := m["u"].(string)
		assert.True(t, ok)

		i := new(big.Int)
		_, ok = i.SetString(x, 10)
		assert.True(t, ok)

		err = blindedSecrets.Handle.Free()
		assert.NoError(t, err)

		jsn, err = blindedSecrets.BlindingFactor.ToJSON()
		assert.NoError(t, err)

		m = map[string]interface{}{}
		err = json.Unmarshal(jsn, &m)
		assert.NoError(t, err)

		x, ok = m["v_prime"].(string)
		assert.True(t, ok)

		i = new(big.Int)
		_, ok = i.SetString(x, 10)
		assert.True(t, ok)

		err = blindedSecrets.BlindingFactor.Free()
		assert.NoError(t, err)

		jsn, err = blindedSecrets.CorrectnessProof.ToJSON()
		assert.NoError(t, err)

		err = blindedSecrets.CorrectnessProof.Free()
		assert.NoError(t, err)

		m = map[string]interface{}{}
		err = json.Unmarshal(jsn, &m)
		assert.NoError(t, err)

		x, ok = m["c"].(string)
		assert.True(t, ok)

		i = new(big.Int)
		_, ok = i.SetString(x, 10)
		assert.True(t, ok)

	})
}

func createBlindedSecrets(t *testing.T, credDef *CredentialDef, nonce *Nonce, vals map[string]interface{}) *BlindedCredentialSecrets {

	values := createValues(t, vals)

	blindedSecrets, err := BlindCredentialSecrets(credDef.PubKey, credDef.KeyCorrectnessProof, nonce, values)
	assert.NoError(t, err)

	return blindedSecrets
}

func createSignature(t *testing.T, fields []string, vals map[string]interface{}) (*CredentialSignature, *CredentialSignatureCorrectnessProof) {
	var nonfields []string
	var err error

	ms, err := NewMasterSecret()
	assert.NoError(t, err)
	js, err := ms.ToJSON()
	assert.NoError(t, err)
	m := struct {
		MasterSecret string `json:"ms"`
	}{}
	err = json.Unmarshal(js, &m)
	assert.NoError(t, err)

	vals["master_secret"] = m.MasterSecret

	nonce, err := NewNonce()
	assert.NoError(t, err)

	credDef := createCredentialDefinition(t, fields, nonfields)
	blindedSecrets := createBlindedSecrets(t, credDef, nonce, vals)
	values := createValues(t, vals)

	signParams := NewSignatureParams()
	signParams.ProverID = "did:sov:example1"
	signParams.CredentialPubKey = credDef.PubKey
	signParams.CredentialPrivKey = credDef.PrivKey
	signParams.BlindedCredentialSecrets = blindedSecrets.Handle
	signParams.BlindedCredentialSecretsCorrectnessProof = blindedSecrets.CorrectnessProof
	signParams.CredentialNonce = nonce
	signParams.CredentialValues = values

	signParams.CredentialIssuanceNonce, err = NewNonce()
	assert.NoError(t, err)

	sig, sigCorrectnessProof, err := signParams.SignCredential()
	assert.NoError(t, err)

	err = values.Free()
	assert.NoError(t, err)

	return sig, sigCorrectnessProof
}
