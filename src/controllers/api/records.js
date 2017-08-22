import logger from '../../utils/logger'
import util from 'util'
import redis from 'redis'
import config from 'config'

const exec = util.promisify(require('child_process').exec)
const log = logger(module)
const recordsController = {}
const redisUrl = config.get('Customer.redisUrl')
const client = redis.createClient(redisUrl)
client.select(1)

const clientHgetall = util.promisify(client.hgetall).bind(client)
const clientHmset = util.promisify(client.hmset).bind(client)

const patternUrl = /(?:\w+\.){1,}\w+/

async function query (d) {
  const cmdStr = `/home/cyber/http_query_tool.tool ${d} www.cloud.urlsec.qq.com 140 rVQ25ruX3GeqQsiCJCWZHvcZaOxRdcB7 80 1.0`
  const { stdout, stderr } = await exec(cmdStr)
  if (stderr) {
    return null
  } else {
    const data = stdout.match(/\{"echostr".*\}/)[0]
    return JSON.parse(data)['url_attr'][0]
  }
}

recordsController.show = async (ctx, next) => {
/* 注意这里有两个正则：
正则1. 规范dname，只要域名，不需要协议类型，例如http://www.baidu.com，则只需要baidu.com，此外防止别人使用api查询时使用垃圾数据，导致将大量垃圾数据写入数据库
正则2. 有些域名的二级域名仍然是公用顶级域名，此时获取三级域名 */
  try {
    const dnameMatch = ctx.query.dname.match(patternUrl)
    let rv = {}
    if (dnameMatch) {
      const dname = dnameMatch[0]
      const record = await clientHgetall(dname)
      if (record) {
        delete record.eviltype
        rv = record
      } else {
        // 这里将来还要加上去查询腾讯的接口，并且插回redis缓存:  <22-08-17, GuoYangyun> //
        // const queryRecord = await query(dname)
        // await clientHmset(queryRecord)
        rv = {dname: dname, urltype: 0, evilclass: 0}
      }
    } else {
      rv = {dname: ctx.query.dname, urltype: 0, evilclass: 0}
    }
    ctx.rest({
      code: 'success',
      message: 'Showed a domain name successfully',
      data: rv
    })
  } catch (e) {
    log.error(e)
    if (e instanceof ctx.APIError) {
      throw e
    } else {
      throw new ctx.APIError('records:show_error', e)
    }
  }
}

recordsController.display = async (ctx, next) => {
  try {
    const dnamesOld = ctx.request.body
    if (dnamesOld.length > 20) {
      throw new ctx.APIError('records:display_error', 'MAX limit 20/request')
    }
    const dnamesWell = []
    const dnamesIll = []
    // 这里采用forEach的方式进行不规范的域名分组
    dnamesOld.forEach(dname => {
      try {
        const tmp = dname.match(patternUrl)[0]
        dnamesWell.push(tmp)
      } catch (e) {
        dnamesIll.push(dname)
      }
    })
    const recordsIll = dnamesIll.map(dname => ({dname: dname, urltype: 0, evilclass: 0}))
    // 这里采用先map出结果，再过滤出非null值，再求差集的方式进行分组，之所以不直接使用forEach分组是因为Promise.all的运用
    const result = await Promise.all(dnamesWell.map(dname => clientHgetall(dname))).catch([])
    const recordsWell1 = result.filter(x => x ? true : false)
    const seenDnames = recordsWell1.map(record => record.dname)
    const notSeenDnames = dnamesWell.filter(dname => {
      if (seenDnames.includes(dname)) {
        return false
      } else {
        return true
      }
    })
    let recordsWell2 = []
    if (notSeenDnames) {
      /* const queriedRecords = await Promise.all(notSeenDnames.map(query)).catch(e => [])
      await Promise.all(queriedRecords.map(record => {
        let dname = record.dname
        delete record.dname
        clientHmset(dname, record)
      }))
      recordsWell2 = queriedRecords.map(x => ({dname: x.url, urltype: x.urltype, evilclass: x.evilclass})) */
      // 这里将来还要加上去查询腾讯的接口，并且插回redis缓存:  <22-08-17, GuoYangyun>
      recordsWell2 = notSeenDnames.map(dname => ({dname: dname, urltype: 0, evilclass: 0}))
    }
    const rv = [...recordsWell1, ...recordsWell2, ...recordsIll]
    rv.map(x => delete x.eviltype)
    ctx.rest({
      code: 'success',
      message: 'Displayed some domain names successfully',
      data: rv
    })
  } catch (e) {
    log.error(e)
    if (e instanceof ctx.APIError) {
      throw e
    } else {
      throw new ctx.APIError('records:display_error', e)
    }
  }
}

export default recordsController
