/*!
 * Copyright (c) 2023-2024 Digital Bazaar, Inc. All rights reserved.
 */
import {CIPHERSUITES} from '../lib/bbs/ciphersuites.js';
import {os2ip} from '../lib/bbs/util.js';

const TEXT_ENCODER = new TextEncoder();

export const MESSAGES = [
  h2b('9872ad089e452c7b6e283dfac2a80d58e8d0ff71cc4d5e310a1debdda4a45f02'),
  h2b('c344136d9ab02da4dd5908bbba913ae6f58c2cc844b802a6f811f5fb075f9b80'),
  h2b('7372e9daa5ed31e6cd5c825eac1b855e84476a1d94932aa348e07b73'),
  h2b('77fe97eb97a1ebe2e81e4e3597a3ee740a66e9ef2412472c'),
  h2b('496694774c5604ab1b2544eababcf0f53278ff50'),
  h2b('515ae153e22aae04ad16f759e07237b4'),
  h2b('d183ddc6e2665aa4e2f088af'),
  h2b('ac55fb33a75909ed'),
  h2b('96012096'),
  h2b('')
];

/* eslint-disable max-len */
export const BLS12381_SHAKE256 = {
  ciphersuite: CIPHERSUITES.BLS12381_SHAKE256,
  key_material: h2b('746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579'),
  key_info: h2b('746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e'),
  key_dst: h2b('4242535f424c53313233383147315f584f463a5348414b452d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f'),
  SK: h2s('2eee0f60a8a3a8bec0ee942bfd46cbdae9a0738ee68f5a64e7238311cf09a079'),
  PK: h2b('92d37d1d6cd38fea3a873953333eab23a4c0377e3e049974eb62bd45949cdeb18fb0490edcd4429adff56e65cbce42cf188b31bddbd619e419b99c2c41b38179eb001963bc3decaae0d9f702c7a8c004f207f46c734a5eae2e8e82833f3e7ea5'),
  message_scalars: [
    h2s('1e0dea6c9ea8543731d331a0ab5f64954c188542b33c5bbc8ae5b3a830f2d99f'),
    h2s('3918a40fb277b4c796805d1371931e08a314a8bf8200a92463c06054d2c56a9f'),
    h2s('6642b981edf862adf34214d933c5d042bfa8f7ef343165c325131e2ffa32fa94'),
    h2s('33c021236956a2006f547e22ff8790c9d2d40c11770c18cce6037786c6f23512'),
    h2s('52b249313abbe323e7d84230550f448d99edfb6529dec8c4e783dbd6dd2a8471'),
    h2s('2a50bdcbe7299e47e1046100aadffe35b4247bf3f059d525f921537484dd54fc'),
    h2s('0e92550915e275f8cfd6da5e08e334d8ef46797ee28fa29de40a1ebccd9d95d3'),
    h2s('4c28f612e6c6f82f51f95e1e4faaf597547f93f6689827a6dcda3cb94971d356'),
    h2s('1db51bedc825b85efe1dab3e3ab0274fa82bbd39732be3459525faf70f197650'),
    h2s('27878da72f7775e709bb693d81b819dc4e9fa60711f4ea927740e40073489e78')
  ],
  generators: [
    h2b('a9d40131066399fd41af51d883f4473b0dcd7d028d3d34ef17f3241d204e28507d7ecae032afa1d5490849b7678ec1f8'),
    h2b('903c7ca0b7e78a2017d0baf74103bd00ca8ff9bf429f834f071c75ffe6bfdec6d6dca15417e4ac08ca4ae1e78b7adc0e'),
    h2b('84321f5855bfb6b001f0dfcb47ac9b5cc68f1a4edd20f0ec850e0563b27d2accee6edff1a26b357762fb24e8ddbb6fcb'),
    h2b('b3060dff0d12a32819e08da00e61810676cc9185fdd750e5ef82b1a9798c7d76d63de3b6225d6c9a479d6c21a7c8bf93'),
    h2b('8f1093d1e553cdead3c70ce55b6d664e5d1912cc9edfdd37bf1dad11ca396a0a8bb062092d391ebf8790ea5722413f68'),
    h2b('990824e00b48a68c3d9a308e8c52a57b1bc84d1cf5d3c0f8c6fb6b1230e4e5b8eb752fb374da0b1ef687040024868140'),
    h2b('b86d1c6ab8ce22bc53f625d1ce9796657f18060fcb1893ce8931156ef992fe56856199f8fa6c998e5d855a354a26b0dd'),
    h2b('b4cdd98c5c1e64cb324e0c57954f719d5c5f9e8d991fd8e159b31c8d079c76a67321a30311975c706578d3a0ddc313b7'),
    h2b('8311492d43ec9182a5fc44a75419b09547e311251fe38b6864dc1e706e29446cb3ea4d501634eb13327245fd8a574f77'),
    h2b('ac00b493f92d17837a28d1f5b07991ca5ab9f370ae40d4f9b9f2711749ca200110ce6517dc28400d4ea25dddc146cacc'),
    h2b('965a6c62451d4be6cb175dec39727dc665762673ee42bf0ac13a37a74784fbd61e84e0915277a6f59863b2bb4f5f6005')
  ],
  mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XOF:SHAKE-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_')
  },
  random_scalars: [
    h2s('1004262112c3eaa95941b2b0d1311c09c845db0099a50e67eda628ad26b43083'),
    h2s('6da7f145a94c1fa7f116b2482d59e4d466fe49c955ae8726e79453065156a9a4'),
    h2s('05017919b3607e78c51e8ec34329955d49c8c90e4488079c43e74824e98f1306'),
    h2s('4d451dad519b6a226bba79e11b44c441f1a74800eecfec6a2e2d79ea65b9d32d'),
    h2s('5e7e4894e6dbe68023bc92ef15c410b01f3828109fc72b3b5ab159fc427b3f51'),
    h2s('646e3014f49accb375253d268eb6c7f3289a1510f1e9452b612dd73a06ec5dd4'),
    h2s('363ecc4c1f9d6d9144374de8f1f7991405e3345a3ec49dd485a39982753c11a4'),
    h2s('12e592fe28d91d7b92a198c29afaa9d5329a4dcfdaf8b08557807412faeb4ac6'),
    h2s('513325acdcdec7ea572360587b350a8b095ca19bdd8258c5c69d375e8706141a'),
    h2s('6474fceba35e7e17365dde1a0284170180e446ae96c82943290d7baa3a6ed429')
  ]
};
// convert generator to points
BLS12381_SHAKE256.generators = BLS12381_SHAKE256.generators.map(
  g => BLS12381_SHAKE256.ciphersuite.octets_to_point_E1(g));
BLS12381_SHAKE256.generators.Q_1 = BLS12381_SHAKE256.generators[0];
BLS12381_SHAKE256.generators.H = BLS12381_SHAKE256.generators.slice(1);

BLS12381_SHAKE256.fixtures = [{
  name: 'Message Generators',
  operation: 'create_generators',
  parameters: {
    count: MESSAGES.length + 1,
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHAKE256.ciphersuite.ciphersuite_id + 'H2G_HM2S_'),
    // must compress points to match test vectors
    compress: true
  },
  output: BLS12381_SHAKE256.generators
}, {
  name: 'Message Scalars',
  operation: 'messages_to_scalars',
  parameters: {
    messages: MESSAGES.slice(),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHAKE256.ciphersuite.ciphersuite_id + 'H2G_HM2S_')
  },
  output: BLS12381_SHAKE256.message_scalars
}, {
  name: 'Random Scalars',
  operation: 'mocked_calculate_random_scalars',
  parameters: {
    count: BLS12381_SHAKE256.random_scalars.length,
    ...BLS12381_SHAKE256.mocked_random_scalars_options
  },
  output: BLS12381_SHAKE256.random_scalars
}, {
  name: 'Valid Single Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [MESSAGES[0]]
  },
  // signature
  output: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
  debug: {
    B: h2b('8bbc8c123d3f128f206dd0d2dae490e82af08b84e8d70af3dc291d32a6e98f635beefcc4533b2599804a164aabe68d7c'),
    domain: h2b('2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9')
  }
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES
  },
  // signature
  output: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
  debug: {
    B: h2b('ae8d4ebe248b9ad9c933d5661bfb46c56721fba2a1182ddda7e8fb443bda3c0a571ad018ad31d0b6d1f4e8b985e6c58d'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'No Header Valid Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHAKE256.SK,
    PK: BLS12381_SHAKE256.PK,
    header: h2b(''),
    messages: MESSAGES
  },
  // signature
  output: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
  debug: {
    B: h2b('8607ebc413b397c1e27ce591d1daa39f73da329018bda0f90bf996355cc28c3cdba19feeb81e35be9e1503a018e4086e'),
    domain: h2b('333d8686761cff65a3a2ef20bfa217d37bdf19105e87c210e9ce64ea1210a157'),
  }
}, {
  name: 'Valid Single Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [MESSAGES[0]],
  },
  output: true
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'No Header Valid Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
    header: h2b(''),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'Modified Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    messages: [h2b('')]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Missing Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Reordered Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: MESSAGES.slice().reverse()
  },
  output: false
}, {
  name: 'Wrong Public Key Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: h2b('b24c723803f84e210f7a95f6265c5cbfa4ecc51488bf7acf24b921807801c0798b725b9a2dcfa29953efcdfef03328720196c78b2e613727fd6e085302a0cc2d8d7e1d820cf1d36b20e79eee78c13a1a5da51a298f1aef86f07bc33388f089d8'),
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Wrong Header Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    header: h2b('ffeeddccbbaa00998877665544332211'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('aa74110474fcb00285be4fef3189da207720a7fbc84e3afae2c75b12d936f365c86c9ac5fa39119ef5e094d151bfef0f'),
    T2: h2b('988f3d473186634e41478dc4527cf240e64de23a763037454d39a876862ebc617738ba6c458142e3746b01eab58ca8d7'),
    domain: h2b('2f18dd269c11c512256a9d1d57e61a7d2de6ebcf41cac3053f37afedc4e650a9')
  }
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('8aae12173b9fc9032a603c9e61b0c3dfa9b8d0c4428d7acba4317aa90354ed3fff1afb720cd0e15a912eb2d7ece8037f'),
    T2: h2b('a49f953636d3651a3ae6fe45a99a2e4fec079eef3be8b8a6a4ba70885d7e028642f7224e9f451529915c88a7edc59fbe'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af36ac442df87545e0e8303260a97a0d251de15fc1447b82fff6b47ffb0ff94022869b315dc48c9302523b2715ddec9f56975a0892f5f3aeed3203c29c7a03cfc79187eef45f72b7c5bf0d4fc852adcc7528c05b0ba9554f2eb9b39c168a4dd6bdc3ac603ce14856184f6d713139f9d3930efcc9842e724517dbccff6912088b399447ff786e2f9db8b1061cc89a1636ba9282344729bcd19228ccde2318286c5a115baaf317b48341ac7906c6cc957f94b060351563907dca7f598a4cbdaeab26c4a4fcb6aa7ff6fd999c5f9bc0c9a9b0e4f4a3301de901a6c68b174ed24ccf5cd0cac6726766c91aded6947c4b446a9dfc8ec0aa11ec9ddda57dcc22c554a83a25471be93ae69ad9234b1fc3d133550d7ff570a4bc6555cd0bf23ee1b2a994b2434ea222bc221ba1615adc53b47ba99fc5a66495585d4c86f1f0aecb18df802b8'),
  debug: {
    random_scalars: {
      r1: h2s('5ee9426ae206e3a127eb53c79044bc9ed1b71354f8354b01bf410a02220be7d0'),
      r2: h2s('280d4fcc38376193ffc777b68459ed7ba897e2857f938581acf95ae5a68988f3'),
      e_tilde: h2s('39966b00042fc43906297d692ebb41de08e36aada8d9504d4e0ae02ad59e9230'),
      r1_tilde: h2s('61f5c273999b0b50be8f84d2380eb9220fc5a88afe144efc4007545f0ab9c089'),
      r3_tilde: h2s('63af117e0c8b7d2f1f3e375fcf5d9430e136ff0f7e879423e49dadc401a50089'),
      m_tilde_scalars: [
        h2s('020b83ca2ab319cba0744d6d58da75ac3dfb6ba682bfce2587c5a6d86a4e4e7b'),
        h2s('5bf565343611c08f83e4420e8b1577ace8cc4df5d5303aeb3c4e425f1080f836'),
        h2s('049d77949af1192534da28975f76d4f211315dce1e36f93ffcf2a555de516b28'),
        h2s('407e5a952f145de7da53533de8366bbd2e0c854721a204f03906dc82fde10f48'),
        h2s('1c925d9052849edddcf04d5f1f0d4ff183a66b66eb820f59b675aee121cfc63c'),
        h2s('07d7c41b02158a9c5eac212ed6d7c2cddeb8e38baea6e93e1a00b2e83e2a0995')
      ]
    },
    T1: h2b('8bec86c26337655162b39f97e38ee5c0bbd2b6e8900d1d68fc4c27679dbe88dc76f313526bc800dd3209bef6b8907e95'),
    T2: h2b('8655584d3da1313f881f48c239384a5623d2d292f08dae7ac1d8129c19a02a89b82fa45de3f6c2c439510fce5919656f'),
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('ada2a57ae3d869255d1533f74317b131ad4f0f24cae413ac40028d70f0cf0372b503ff6e705220532727002b8958ebf987e2e8378984afe3214511b9feeee830ffe3121ed005d2c382c04e6db37b646bc2f7002f3699648570fe9b67a0a5aac995644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a5d1d9e6bd05a4dee6a50dd277ffc646f6b676faadceff172a0002325e7f22f47ed9b5125f30dd5fffe9ed1dc99dc283100cb702fa63aaef1bd1f530a5368ca4c7e78a01c7fcc3563b25c6c10c0e063092cbe2590fdfcc7b6a2859e482796f1f6783a41dfdf133ce28d13071b77cbe7fe06bf6e138bd3323e7edc4a6ec9942bfa0b6d1287836e2b1c2db84833d8325d145e6d2a3e94ddd5b6f58c1d1b2a15a854f7cf46711239ebe522bf5e428131e31e2f5f322eba2399fa7a8efec4be722dcaf6ec6adaf84af72c3d7690072d07928045327f3a6587102b066fb9cf96b27aca7f5698a2ec66d04efa05ed57fd6ac27636322c013a168100b733269e9bd6f23d7562affebafc3d9b3c5f54a0c57216b733f8ecb24dc292c17e18b6b8e0f3b8303dfaedee84fba02d491994b95f965deb3c1295545bb9802d98449d98d1af18e9c60536146cfa7aa267bd888b25552dd2'),
  debug: {
    challenge: h2s('1cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652')
  }
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHAKE256.mocked_random_scalars_options
  },
  // proof
  output: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af37286b5d6012208605b7c3fe5457936db502aa7eec43ae4a9d1bdf5f675153d521b1e587c6ddd195e80358667aae42e64754595a0d35c1d6e72f147f67f591c823e75340360615b9c0173445afe53002d4face239979f697eff7183826449d4dc285a15e0c6afec9289b0b39e0741d0c4925c090f722569b8c64e2829904a02ec1ab6340cfe999a59196bbb8da2be2a89ddd84378dba0a22533e76fd6ac14f2b52a3972b041950539c19debaf7454e6ef3b9cec23086dc26b8a104e319aa4394e4e376c133d6c00133daf2f414e1df8ebca2de0a23e6ba37663f8074b9c8f440e37459bc08a8a4a587b78b2102c81b2f48f0fa73c331f7b6f64f6d8d50f3f8cb1424626f9cf3171cdea7f8cedb7bbb5a269856b37e8ba16ba8604fb1681be22dc6b64827a8326691524b7c05ac462ec8d8eee64bc6e09df622bb974fba93a75f8'),
  debug: {
    domain: h2b('6f7ee8de30835599bb540d2cb4dd02fd0c6cf8246f14c9ee9a8463f7fd400f7b')
  }
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: true
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: true
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af36ac442df87545e0e8303260a97a0d251de15fc1447b82fff6b47ffb0ff94022869b315dc48c9302523b2715ddec9f56975a0892f5f3aeed3203c29c7a03cfc79187eef45f72b7c5bf0d4fc852adcc7528c05b0ba9554f2eb9b39c168a4dd6bdc3ac603ce14856184f6d713139f9d3930efcc9842e724517dbccff6912088b399447ff786e2f9db8b1061cc89a1636ba9282344729bcd19228ccde2318286c5a115baaf317b48341ac7906c6cc957f94b060351563907dca7f598a4cbdaeab26c4a4fcb6aa7ff6fd999c5f9bc0c9a9b0e4f4a3301de901a6c68b174ed24ccf5cd0cac6726766c91aded6947c4b446a9dfc8ec0aa11ec9ddda57dcc22c554a83a25471be93ae69ad9234b1fc3d133550d7ff570a4bc6555cd0bf23ee1b2a994b2434ea222bc221ba1615adc53b47ba99fc5a66495585d4c86f1f0aecb18df802b8'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('ada2a57ae3d869255d1533f74317b131ad4f0f24cae413ac40028d70f0cf0372b503ff6e705220532727002b8958ebf987e2e8378984afe3214511b9feeee830ffe3121ed005d2c382c04e6db37b646bc2f7002f3699648570fe9b67a0a5aac995644ee738810772d90c1033f1dfe45c0b1b453d131170aafa8a99f812f3b90a5d1d9e6bd05a4dee6a50dd277ffc646f6b676faadceff172a0002325e7f22f47ed9b5125f30dd5fffe9ed1dc99dc283100cb702fa63aaef1bd1f530a5368ca4c7e78a01c7fcc3563b25c6c10c0e063092cbe2590fdfcc7b6a2859e482796f1f6783a41dfdf133ce28d13071b77cbe7fe06bf6e138bd3323e7edc4a6ec9942bfa0b6d1287836e2b1c2db84833d8325d145e6d2a3e94ddd5b6f58c1d1b2a15a854f7cf46711239ebe522bf5e428131e31e2f5f322eba2399fa7a8efec4be722dcaf6ec6adaf84af72c3d7690072d07928045327f3a6587102b066fb9cf96b27aca7f5698a2ec66d04efa05ed57fd6ac27636322c013a168100b733269e9bd6f23d7562affebafc3d9b3c5f54a0c57216b733f8ecb24dc292c17e18b6b8e0f3b8303dfaedee84fba02d491994b95f965deb3c1295545bb9802d98449d98d1af18e9c60536146cfa7aa267bd888b25552dd2'),
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('853f4927bd7e4998af27df65566c0a071a33a5207d1af33ef7c3be04004ac5da860f34d35c415498af32729720ca4d92977bbbbd60fdc70ddbb2588878675b90815273c9eaf0caa1123fe5d0c4833fefc459d18e1dc83d669268ec702c0e16a6b73372346feb94ab16189d4c525652b8d3361bab43463700720ecfb0ee75e595ea1b13330615011050a0dfcffdb21af37286b5d6012208605b7c3fe5457936db502aa7eec43ae4a9d1bdf5f675153d521b1e587c6ddd195e80358667aae42e64754595a0d35c1d6e72f147f67f591c823e75340360615b9c0173445afe53002d4face239979f697eff7183826449d4dc285a15e0c6afec9289b0b39e0741d0c4925c090f722569b8c64e2829904a02ec1ab6340cfe999a59196bbb8da2be2a89ddd84378dba0a22533e76fd6ac14f2b52a3972b041950539c19debaf7454e6ef3b9cec23086dc26b8a104e319aa4394e4e376c133d6c00133daf2f414e1df8ebca2de0a23e6ba37663f8074b9c8f440e37459bc08a8a4a587b78b2102c81b2f48f0fa73c331f7b6f64f6d8d50f3f8cb1424626f9cf3171cdea7f8cedb7bbb5a269856b37e8ba16ba8604fb1681be22dc6b64827a8326691524b7c05ac462ec8d8eee64bc6e09df622bb974fba93a75f8'),
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'Modified Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [h2b('')],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0], MESSAGES[1]],
    disclosed_indexes: [0, 1]
  },
  output: false
}, {
  name: 'Missing Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES.slice(0, 9),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8]
  },
  output: false
}, {
  name: 'Reordered Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('80ff9367fda28896618e8ede02481d660fe80bfce51a46bebe7e1d6a4c751d60e09e87cd8d1e2a078d0838de56b6a7ca94651eec82e5f689b4dfc7e3c879ff7e33906271b17af20eab678d64903515971e39484e712fd3c8a45f279c1e058955b3dd7ed57aaadc348361e2501a17317352e555a333e014e8e7d71eef808ae4f8fbdf45cd19fde45038bb310d5135f5205611672c8d50d505af8a6e038729230458a6ceb663fa048f4ce3a7a92998de4200882156ba6b6e60d855c0645d2fdd628518d2e6fc5221b7456ccbc1c5210a1704e4d662dddd1f99a767344a7944ab7f9b6f9d9069de4a132e4feebb6d70a87b0856635e1b8b8ca49e2992f8c80221398e08935824f959a821b4120cdfb5e6be'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES.slice().reverse(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: false
}, {
  name: 'Wrong Public Key Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: h2b('b24c723803f84e210f7a95f6265c5cbfa4ecc51488bf7acf24b921807801c0798b725b9a2dcfa29953efcdfef03328720196c78b2e613727fd6e085302a0cc2d8d7e1d820cf1d36b20e79eee78c13a1a5da51a298f1aef86f07bc33388f089d8'),
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Wrong Header Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
    header: h2b('ffeeddccbbaa00998877665544332211'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Wrong Presentation Header Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    proof: h2b('89b485c2c7a0cd258a5d265a6e80aae416c52e8d9beaf0e38313d6e5fe31e7f7dcf62023d130fbc1da747440e61459b1929194f5527094f56a7e812afb7d92ff2c081654c6d5a70e369474267f1c7f769d47160cd92d79f66bb86e994c999226b023d58ee44d660434e6ba60ed0da1a5d2cde031b483684cd7c5b13295a82f57e209b584e8fe894bcc964117bf3521b468cc9c6ba22419b3e567c7f72b6af815ddeca161d6d5270c3e8f269cdabb7d60230b3c66325dcf6caf39bcca06d889f849d301e7f30031fdeadc443a7575de547259ffe5d21a45e5a0da9b113512f7b124f031b0b8329a8625715c9245033ae13dfadd6bdb0b4364952647db3d7b91faa4c24cbb65344c03473c5065bb414ff7'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('98eb37fceb31115bf647f2983aef578ad895e55f7451b1add02fa738224cb89a31b148eace4d20d001be31d162c58d12574f30e68665b6403956a83b23a16f1daceacce8c5fde25d3defd52d6d5ff2e1'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: true
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: true
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('abfa513cdb323e47214b7c182fb623197a0681b753f897545a73d82ee133a8ecf69db9aa09fe425df4e7687d99d779db5c66199c0dc9d2a442d331c43f56e060edc69a69ed2f13de3813b98ce6b05737'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHAKE256.PK,
    signature: h2b('97a296c83ed3626fe254d26021c5e9a087b580f1e8bc91bb51efb04420bfdaca215fe376a0bc12440bcc52224fb33c696cca9239b9f28dcddb7bd850aae9cd1a9c3e9f3639953fe789dbba53b8f0dd6f'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}];
/* eslint-enable max-len */

/* eslint-disable max-len */
export const BLS12381_SHA256 = {
  ciphersuite: CIPHERSUITES.BLS12381_SHA256,
  key_material: h2b('746869732d49532d6a7573742d616e2d546573742d494b4d2d746f2d67656e65726174652d246528724074232d6b6579'),
  key_info: h2b('746869732d49532d736f6d652d6b65792d6d657461646174612d746f2d62652d757365642d696e2d746573742d6b65792d67656e'),
  key_dst: h2b('4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4b455947454e5f4453545f'),
  SK: h2s('60e55110f76883a13d030b2f6bd11883422d5abde717569fc0731f51237169fc'),
  PK: h2b('a820f230f6ae38503b86c70dc50b61c58a77e45c39ab25c0652bbaa8fa136f2851bd4781c9dcde39fc9d1d52c9e60268061e7d7632171d91aa8d460acee0e96f1e7c4cfb12d3ff9ab5d5dc91c277db75c845d649ef3c4f63aebc364cd55ded0c'),
  dst: h2b('4242535f424c53313233383147315f584d443a5348412d3235365f535357555f524f5f4832475f484d32535f4d41505f4d53475f544f5f5343414c41525f41535f484153485f'),
  message_scalars: [
    h2s('1cb5bb86114b34dc438a911617655a1db595abafac92f47c5001799cf624b430'),
    h2s('154249d503c093ac2df516d4bb88b510d54fd97e8d7121aede420a25d9521952'),
    h2s('0c7c4c85cdab32e6fdb0de267b16fa3212733d4e3a3f0d0f751657578b26fe22'),
    h2s('4a196deafee5c23f630156ae13be3e46e53b7e39094d22877b8cba7f14640888'),
    h2s('34c5ea4f2ba49117015a02c711bb173c11b06b3f1571b88a2952b93d0ed4cf7e'),
    h2s('4045b39b83055cd57a4d0203e1660800fabe434004dbdc8730c21ce3f0048b08'),
    h2s('064621da4377b6b1d05ecc37cf3b9dfc94b9498d7013dc5c4a82bf3bb1750743'),
    h2s('34ac9196ace0a37e147e32319ea9b3d8cc7d21870d3c3ba071246859cca49b02'),
    h2s('57eb93f417c43200e9784fa5ea5a59168d3dbc38df707a13bb597c871b2a5f74'),
    h2s('08e3afeb2b4f2b5f907924ef42856616e6f2d5f1fb373736db1cca32707a7d16')
  ],
  generators: [
    h2b('a9ec65b70a7fbe40c874c9eb041c2cb0a7af36ccec1bea48fa2ba4c2eb67ef7f9ecb17ed27d38d27cdeddff44c8137be'),
    h2b('98cd5313283aaf5db1b3ba8611fe6070d19e605de4078c38df36019fbaad0bd28dd090fd24ed27f7f4d22d5ff5dea7d4'),
    h2b('a31fbe20c5c135bcaa8d9fc4e4ac665cc6db0226f35e737507e803044093f37697a9d452490a970eea6f9ad6c3dcaa3a'),
    h2b('b479263445f4d2108965a9086f9d1fdc8cde77d14a91c856769521ad3344754cc5ce90d9bc4c696dffbc9ef1d6ad1b62'),
    h2b('ac0401766d2128d4791d922557c7b4d1ae9a9b508ce266575244a8d6f32110d7b0b7557b77604869633bb49afbe20035'),
    h2b('b95d2898370ebc542857746a316ce32fa5151c31f9b57915e308ee9d1de7db69127d919e984ea0747f5223821b596335'),
    h2b('8f19359ae6ee508157492c06765b7df09e2e5ad591115742f2de9c08572bb2845cbf03fd7e23b7f031ed9c7564e52f39'),
    h2b('abc914abe2926324b2c848e8a411a2b6df18cbe7758db8644145fefb0bf0a2d558a8c9946bd35e00c69d167aadf304c1'),
    h2b('80755b3eb0dd4249cbefd20f177cee88e0761c066b71794825c9997b551f24051c352567ba6c01e57ac75dff763eaa17'),
    h2b('82701eb98070728e1769525e73abff1783cedc364adb20c05c897a62f2ab2927f86f118dcb7819a7b218d8f3fee4bd7f'),
    h2b('a1f229540474f4d6f1134761b92b788128c7ac8dc9b0c52d59493132679673032ac7db3fb3d79b46b13c1c41ee495bca')
  ],
  mocked_random_scalars_options: {
    seed: h2b('332e313431353932363533353839373933323338343632363433333833323739'),
    dst: TEXT_ENCODER.encode('BBS_BLS12381G1_XMD:SHA-256_SSWU_RO_H2G_HM2S_MOCK_RANDOM_SCALARS_DST_')
  },
  random_scalars: [
    h2s('04f8e2518993c4383957ad14eb13a023c4ad0c67d01ec86eeb902e732ed6df3f'),
    h2s('5d87c1ba64c320ad601d227a1b74188a41a100325cecf00223729863966392b1'),
    h2s('0444607600ac70482e9c983b4b063214080b9e808300aa4cc02a91b3a92858fe'),
    h2s('548cd11eae4318e88cda10b4cd31ae29d41c3a0b057196ee9cf3a69d471e4e94'),
    h2s('2264b06a08638b69b4627756a62f08e0dc4d8240c1b974c9c7db779a769892f4'),
    h2s('4d99352986a9f8978b93485d21525244b21b396cf61f1d71f7c48e3fbc970a42'),
    h2s('5ed8be91662386243a6771fbdd2c627de31a44220e8d6f745bad5d99821a4880'),
    h2s('62ff1734b939ddd87beeb37a7bbcafa0a274cbc1b07384198f0e88398272208d'),
    h2s('05c2a0af016df58e844db8944082dcaf434de1b1e2e7136ec8a99b939b716223'),
    h2s('485e2adab17b76f5334c95bf36c03ccf91cef77dcfcdc6b8a69e2090b3156663')
  ]
};
// convert generator to points
BLS12381_SHA256.generators = BLS12381_SHA256.generators.map(
  g => BLS12381_SHA256.ciphersuite.octets_to_point_E1(g));
BLS12381_SHA256.generators.Q_1 = BLS12381_SHA256.generators[0];
BLS12381_SHA256.generators.H = BLS12381_SHA256.generators.slice(1);

BLS12381_SHA256.fixtures = [{
  name: 'Message Generators',
  operation: 'create_generators',
  parameters: {
    count: MESSAGES.length + 1,
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_'),
    // must compress points to match test vectors
    compress: true
  },
  output: BLS12381_SHA256.generators
}, {
  name: 'Message Scalars',
  operation: 'messages_to_scalars',
  parameters: {
    messages: MESSAGES.slice(),
    api_id: TEXT_ENCODER.encode(
      BLS12381_SHA256.ciphersuite.ciphersuite_id + 'H2G_HM2S_')
  },
  output: BLS12381_SHA256.message_scalars
}, {
  name: 'Random Scalars',
  operation: 'mocked_calculate_random_scalars',
  parameters: {
    count: BLS12381_SHA256.random_scalars.length,
    ...BLS12381_SHA256.mocked_random_scalars_options
  },
  output: BLS12381_SHA256.random_scalars
}, {
  name: 'Valid Single Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: [MESSAGES[0]]
  },
  // signature
  output: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
  debug: {
    B: h2b('92d264aed02bf23de022ebe778c4f929fddf829f504e451d011ed89a313b8167ac947332e1648157ceffc6e6e41ab255'),
    domain: h2b('25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c'),
  }
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    messages: MESSAGES,
  },
  // signature
  output: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
  debug: {
    B: h2b('84f48376f7df6af40bc329cf484cdbfd0b19d0b326fccab4e9d8f00d1dbcf48139d498b19667f203cf8a1d1f8340c522'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'No Header Valid Signature',
  operation: 'Sign',
  parameters: {
    SK: BLS12381_SHA256.SK,
    PK: BLS12381_SHA256.PK,
    header: h2b(''),
    messages: MESSAGES
  },
  // signature
  output: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
  debug: {
    B: h2b('98e38eadb6a2232cf91f41861089cda14d7e3ddef0c6eaba4d11a2732f66408f394d58301ffcc8fcfb3c89bb75136f61'),
    domain: h2b('41c5fe0290d0da734ce9bba57bfe0dfc14f3f9cfef18a0d7438cf2075fd71cc7'),
  }
}, {
  name: 'Valid Single Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    messages: [MESSAGES[0]]
  },
  output: true
}, {
  name: 'Valid Multi-Message Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'No Header Valid Signature',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b(''),
    signature: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
    messages: MESSAGES
  },
  output: true
}, {
  name: 'Modified Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    messages: [h2b('')]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Missing Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: [MESSAGES[0], MESSAGES[1]]
  },
  output: false
}, {
  name: 'Reordered Message Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES.slice().reverse()
  },
  output: false
}, {
  name: 'Wrong Public Key Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: h2b('b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6'),
    header: h2b('11223344556677889900aabbccddeeff'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Wrong Header Signature (negative)',
  operation: 'Verify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    header: h2b('ffeeddccbbaa00998877665544332211'),
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    messages: MESSAGES
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
  debug: {
    random_scalars: {
      r1: h2s('60ca409f6b0563f687fc471c63d2819f446f39c23bb540925d9d4254ac58f337'),
      r2: h2s('2ceff4982de0c913090f75f081df5ec594c310bb48c17cfdaab5332a682ef811'),
      e_tilde: h2s('6101c4404895f3dff87ab39c34cb995af07e7139e6b3847180ffdd1bc8c313cd'),
      r1_tilde: h2s('0dfcffd97a6ecdebef3c9c114b99d7a030c998d938905f357df62822dee072e8'),
      r3_tilde: h2s('639e3417007d38e5d34ba8c511e836768ddc2669fdd3faff5c14ad27ac2b2da1'),
      m_tilde_scalars: []
    },
    T1: h2b('8ce960f5155d05a1795cc3422e6c975f6436a9b70c17ffbfd776346c93a9682bb6c74abd70d8c32781ae783ec45ea005'),
    T2: h2b('ab9543a6b04303e997621d3d5cbd85924e7e69da498a2a9e9d3a8b01f39259c9c5920bd530de1d3b0afb99eb0c549d5a'),
    domain: h2b('25d57fab92a8274c68fde5c3f16d4b275e4a156f211ae34b3ab32fbaf506ed5c'),
    // proof details
    Abar: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa'),
    Bbar: h2b('8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2'),
    D: h2b('aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a'),
    eHat: h2s('0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd656'),
    r1Hat: h2s('67373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b3'),
    r3Hat: h2s('3833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070'),
    challenge: h2s('067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980')
  }
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
  debug: {
    random_scalars: {
      r1: h2s('1308e6f945f663b96de1c76461cf7d7f88b92eb99a9034685150db443d733881'),
      r2: h2s('25f81cb69a8fac6fb55d44a084557258575d1003be2bd94f1922dad2c3e447fd'),
      e_tilde: h2s('5e8041a7ab02976ee50226c4b062b47d38829bbf42ee7eb899b29720377a584c'),
      r1_tilde: h2s('3bbf1d5dc2904dbb7b2ba75c5dce8a5ad2d56a359c13ff0fa5fcb1339cd2fe58'),
      r3_tilde: h2s('016b1460eee7707c524a86a4aedeb826ce9597b42906dccaa96c6b49a8ea7da2'),
      m_tilde_scalars: []
    },
    T1: h2b('815064df090feebe9d089343add9ce0c46c55c45a7a75913c3ffe980cd51dd5af5a6b45a10dcf7c56927b3a30c99adea'),
    T2: h2b('b9f8cf9271d10a04ae7116ad021f4b69c435d20a5af10ddd8f5b1ec6b9b8b91605aca76a140241784b7f161e21dfc3e7'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481352bb6fce6084eb1867c71caeac2afc4f57f4d26504656b798b3e4009eb227c7fa41b6ae00daae0436d853e86b32b366b0a9929e1570369e9c61b7b177eb70b7ff27326c467c362120dfeacc0692d25ccdd62d733ff6e8614abd16b6b63a7b78d11632cf41bc44856aee370fee6690a637b3b1d8d8525aff01cd3555c39d04f8ee1606964c2da8b988897e3d27cb444b8394acc80876d3916c485c9f36098fed6639f12a6a6e67150a641d7485656408e9ae22b9cb7ec77e477f71c1fe78cab3ee5dd62c34dd595edb15cbce061b29192419dfadcdee179f134dd8feb9323c426c51454168ffacb65021995848e368a5c002314b508299f67d85ad0eaaaac845cb029927191152edee034194cca3ae0d45cbd2f5e5afd1f9b8a3dd903adfa17ae43a191bf3119df57214f19e662c7e01e8cc2eb6b038bc7d707f2f3e13545909e0'),
  debug: {
    random_scalars: {
      r1: h2s('44679831fe60eca50938ef0e812e2a9284ad7971b6932a38c7303538b712e457'),
      r2: h2s('6481692f89086cce11779e847ff884db8eebb85a13e81b2d0c79d6c1062069d8'),
      e_tilde: h2s('721ce4c4c148a1d5826f326af6fd6ac2844f29533ba4127c3a43d222d51b7081'),
      r1_tilde: h2s('1ecfaf5a079b0504b00a1f0d6fe8857291dd798291d7ad7454b398114393f37f'),
      r3_tilde: h2s('0a4b3d59b34707bb9999bc6e2a6d382a2d2e214bff36ecd88639a14124b1622e'),
      m_tilde_scalars: [
        h2s('7217411a9e329c7a5705e8db552274646e2949d62c288d7537dd62bc284715e4'),
        h2s('67d4d43660746759f598caac106a2b5f58ccd1c3eefaec31841a4f77d2548870'),
        h2s('715d965b1c3912d20505b381470ff1a528700b673e50ba89fd287e13171cc137'),
        h2s('4d3281a149674e58c9040fc7a10dd92cb9c7f76f6f0815a1afc3b09d74b92fe4'),
        h2s('438feebaa5894ca0da49992df2c97d872bf153eab07e08ff73b28131c46ff415'),
        h2s('602b723c8bbaec1b057d70f18269ae5e6de6197a5884967b03b933fa80006121')
      ]
    },
    T1: h2b('896e010e182f0718400b1e694ebc740215c2dd703f5988b7312be5a7f824f86b221dd89d7a66f61b9fb238a73169e3bb'),
    T2: h2b('8f5f191c956aefd5c960e57d2dfbab6761eb0ebc5efdba1aca1403dcc19e05296b16c9feb7636cb4ef2a360c5a148483'),
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('958783d7d535fe1860a71ad5a7cf42df6527246300e3f3d94d67639c7e8a7dbcf3f082f63e3b1bcc1cdad71e1f6d5f0d821c4c6bb4b2dcdfe945491d4f4a23d10752431d364fcbdd199c753f0beee7ffe02abbad57384244294ef7c2031d9c50ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db36771c74f1feec7f67b30e3805d71c8f893837b455d734d360c80e119b00dc63e2756b81a320d659a9a0f1ee57c41773f304c37c278d169faec5f6720bb9187e9333b793a57ba69f27e4b0c2ea35271276fc0011306d6c909cf4d4a7a50dbc9f6ef35d43e2043046dc3041ac0a9b893dfd2dcd147910d719e818b4189a76f791a3600acd76623573c1796262a3914921ec504d0f727c63e16b432f6256db62b9667016e516e97e2ef0bfa3bd192306564df28e019af18c50ca86a0e1d8d6b08b0641e549accd5e34ada8903d55021780865edfa70f63b85f0ddaf50787f8ced8eee658f2dd61673d2cbeca2aa2a5b649c22501b72cc7ee2d10bc9fe3aa3a7e169dc070d90b37735488cd0c27517ffd634b99c1dc016a4086d24feff6f19f3c92fa11cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652'),
  debug: {
    domain: h2b('41c5fe0290d0da734ce9bba57bfe0dfc14f3f9cfef18a0d7438cf2075fd71cc7'),
    challenge: h2s('1cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652')
  }
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGen',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6],
    mocked_random_scalars_options:
      BLS12381_SHA256.mocked_random_scalars_options
  },
  // proof
  output: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356d60aa96c9b53ff5c63b3930bbcb3940f2132b7dcd800be4afbffd3325ecedaf033d354de52e12e924b32dd13c2f7cebef3614a4a519ff94d1bcceb7e22562ab4a5729a74cc3746558e25469651d7da37f714951c2ca03fc364a2272d13b2dee53412f97f42dfd6b57ae92fc7cb4859f418d6a912f5c446002cbf96ee6b8f4a849577a43ef303592c33e03608a9ca93066084bdfb3d3974ba322b7523d48fc9b35227e776c994b0e2da1587b496660836a7307a2125eae5912be3ea839bb4db16a21cc394c9a63fce91040d8321b30313677f7cbc4a9119fd0849aacef25fe9336db2dcbd85a2e3fd2ca2efff623c13e6c48b832c9e07dbe4337320dd0264a573f25bb46876e8153db47de2f0176db68cca1f55406a78c89c1a65716c00e9230098c6a9690a190b20720a7662ccd13b392fe08d045b99d5010f625cd74f7e90a'),
  debug: {
    domain: h2b('6272832582a0ac96e6fe53e879422f24c51680b25fbf17bad22a35ea93ce5b47')
  }
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: true
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: true
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481352bb6fce6084eb1867c71caeac2afc4f57f4d26504656b798b3e4009eb227c7fa41b6ae00daae0436d853e86b32b366b0a9929e1570369e9c61b7b177eb70b7ff27326c467c362120dfeacc0692d25ccdd62d733ff6e8614abd16b6b63a7b78d11632cf41bc44856aee370fee6690a637b3b1d8d8525aff01cd3555c39d04f8ee1606964c2da8b988897e3d27cb444b8394acc80876d3916c485c9f36098fed6639f12a6a6e67150a641d7485656408e9ae22b9cb7ec77e477f71c1fe78cab3ee5dd62c34dd595edb15cbce061b29192419dfadcdee179f134dd8feb9323c426c51454168ffacb65021995848e368a5c002314b508299f67d85ad0eaaaac845cb029927191152edee034194cca3ae0d45cbd2f5e5afd1f9b8a3dd903adfa17ae43a191bf3119df57214f19e662c7e01e8cc2eb6b038bc7d707f2f3e13545909e0'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('958783d7d535fe1860a71ad5a7cf42df6527246300e3f3d94d67639c7e8a7dbcf3f082f63e3b1bcc1cdad71e1f6d5f0d821c4c6bb4b2dcdfe945491d4f4a23d10752431d364fcbdd199c753f0beee7ffe02abbad57384244294ef7c2031d9c50ac310574f509c712bb1a181d64ea3c1ee075c018a2bc773e2480b5c033ccb9bfea5af347a88ab83746c9342ba76db36771c74f1feec7f67b30e3805d71c8f893837b455d734d360c80e119b00dc63e2756b81a320d659a9a0f1ee57c41773f304c37c278d169faec5f6720bb9187e9333b793a57ba69f27e4b0c2ea35271276fc0011306d6c909cf4d4a7a50dbc9f6ef35d43e2043046dc3041ac0a9b893dfd2dcd147910d719e818b4189a76f791a3600acd76623573c1796262a3914921ec504d0f727c63e16b432f6256db62b9667016e516e97e2ef0bfa3bd192306564df28e019af18c50ca86a0e1d8d6b08b0641e549accd5e34ada8903d55021780865edfa70f63b85f0ddaf50787f8ced8eee658f2dd61673d2cbeca2aa2a5b649c22501b72cc7ee2d10bc9fe3aa3a7e169dc070d90b37735488cd0c27517ffd634b99c1dc016a4086d24feff6f19f3c92fa11cc198830295ccc56e5f9527216765105eee34324c5f3834154943608a8ca652'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a8da259a5ae7a9a8e5e4e809b8e7718b4d7ab913ed5781ebbff4814c762033eda4539973ed9bf557f882192518318cc4916fdffc857514082915a31df5bbb79992a59fd68dc3b48d19d2b0ad26be92b4cf78a30f472c0fd1e558b9d03940b077897739228c88afc797916dca01e8f03bd9c5375c7a7c59996e514bb952a436afd24457658acbaba5ddac2e693ac481356d60aa96c9b53ff5c63b3930bbcb3940f2132b7dcd800be4afbffd3325ecedaf033d354de52e12e924b32dd13c2f7cebef3614a4a519ff94d1bcceb7e22562ab4a5729a74cc3746558e25469651d7da37f714951c2ca03fc364a2272d13b2dee53412f97f42dfd6b57ae92fc7cb4859f418d6a912f5c446002cbf96ee6b8f4a849577a43ef303592c33e03608a9ca93066084bdfb3d3974ba322b7523d48fc9b35227e776c994b0e2da1587b496660836a7307a2125eae5912be3ea839bb4db16a21cc394c9a63fce91040d8321b30313677f7cbc4a9119fd0849aacef25fe9336db2dcbd85a2e3fd2ca2efff623c13e6c48b832c9e07dbe4337320dd0264a573f25bb46876e8153db47de2f0176db68cca1f55406a78c89c1a65716c00e9230098c6a9690a190b20720a7662ccd13b392fe08d045b99d5010f625cd74f7e90a'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    disclosed_messages: [
      MESSAGES[0],
      MESSAGES[2],
      MESSAGES[4],
      MESSAGES[6]
    ],
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'Modified Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [h2b('')],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Extra Unsigned Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0], MESSAGES[1]],
    disclosed_indexes: [0, 1]
  },
  output: false
}, {
  name: 'Missing Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES.slice(0, 9),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8]
  },
  output: false
}, {
  name: 'Reordered Message Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a6faacf33f935d1910f21b1bbe380adcd2de006773896a5bd2afce31a13874298f92e602a4d35aef5880786cffc5aaf08978484f303d0c85ce657f463b71905ee7c3c0c9038671d8fb925525f623745dc825b14fc50477f3de79ce8d915d841ba73c8c97264177a76c4a03341956d2ae45ed3438ce598d5cda4f1bf9507fecef47855480b7b30b5e4052c92a4360110c322b4cb2d9796ff2d741979226249dc14d4b1fd5ca1a8f6fdfc16f726fc7683e3605d5ec28d331111a22ed81729cbb3c8c3732c7593e445f802fc3169c26857622ed31bc058fdfe68d25f0c3b9615279719c64048ea9cdb74104b27757c2d01035507d39667d77d990ec5bda22c866fcc9fe70bb5b7826a2b4e861b6b8124fbd'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: MESSAGES.slice().reverse(),
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: false
}, {
  name: 'Wrong Public Key Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: h2b('b064bd8d1ba99503cbb7f9d7ea00bce877206a85b1750e5583dd9399828a4d20610cb937ea928d90404c239b2835ffb104220a9c66a4c9ed3b54c0cac9ea465d0429556b438ceefb59650ddf67e7a8f103677561b7ef7fe3c3357ec6b94d41c6'),
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Wrong Header Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
    header: h2b('ffeeddccbbaa00998877665544332211'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Wrong Presentation Header Proof (negative)',
  operation: 'ProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    proof: h2b('a7c217109e29ecab846691eaad757beb8cc93356daf889856d310af5fc5587ea4f8b70b0d960c68b7aefa62cae806baa8edeca19ca3dd884fb977fc43d946dc2a0be8778ec9ff7a1dae2b49c1b5d75d775ba37652ae759b9bb70ba484c74c8b2aeea5597befbb651827b5eed5a66f1a959bb46cfd5ca1a817a14475960f69b32c54db7587b5ee3ab665fbd37b506830a0fdc9a7f71072daabd4cdb49038f5c55e84623400d5f78043a18f76b272fd65667373702763570c8a2f7c837574f6c6c7d9619b0834303c0f55b2314cec804b33833c7047865587b8e55619123183f832021dd97439f324fa3ad90ec45417070067fb8c56b2af454562358b1509632f92f2116c020fe7de1ba242effdb36e980'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    disclosed_messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: false
}, {
  name: 'Valid Single Message Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('88c0eb3bc1d97610c3a66d8a3a73f260f95a3028bccf7fff7d9851e2acd9f3f32fdf58a5b34d12df8177adf37aa318a20f72be7d37a8e8d8441d1bc0bc75543c681bf061ce7e7f6091fe78c1cb8af103'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: [MESSAGES[0]],
    disclosed_indexes: [0]
  },
  output: true
}, {
  name: 'Valid Multi-Message, All Messages Disclosed Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
  },
  output: true
}, {
  name: 'Valid Multi-Message, Some Messages Disclosed Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Header Valid Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('ae0b1807865598b3884e3e9b110e8faec662050dc9b4d95309d957fd30f6fc24161f6f8b5680f1f5d1b547be221547915ca665c7b3087a336d5e0c5fcfea62576afd13e563b730ef6d6d81f9944ab95b'),
    header: h2b(''),
    ph: h2b('bed231d880675ed101ead304512e043ade9958dd0241ea70b4b3957fba941501'),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}, {
  name: 'No Presentation Header Valid Proof',
  operation: 'ProofGenAndProofVerify',
  parameters: {
    PK: BLS12381_SHA256.PK,
    signature: h2b('895cd9c0ccb9aca4de913218655346d718711472f2bf1f3e68916de106a0d93cf2f47200819b45920bbda541db2d91480665df253fedab2843055bdc02535d83baddbbb2803ec3808e074f71f199751e'),
    header: h2b('11223344556677889900aabbccddeeff'),
    ph: h2b(''),
    messages: MESSAGES,
    disclosed_indexes: [0, 2, 4, 6]
  },
  output: true
}];
/* eslint-enable max-len */

export const CIPHERSUITES_TEST_VECTORS = [
  BLS12381_SHAKE256,
  BLS12381_SHA256
];

// hex => bytes
function h2b(hex) {
  if(hex.length === 0) {
    return new Uint8Array();
  }
  return Uint8Array.from(hex.match(/.{1,2}/g).map(h => parseInt(h, 16)));
}

// hex => scalar (bigint)
function h2s(hex) {
  return os2ip(h2b(hex));
}
